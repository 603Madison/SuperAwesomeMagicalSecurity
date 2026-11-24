package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Windows event logs are polled with wevtutil and converted to one JSON
// object per line (source "windows"):
//
//	{"EventID":4625,"TimeCreated":"...","Provider":"...","Channel":"Security",
//	 "Computer":"...","RecordID":123,"Message":"","Data":{...}}
var winChannels = []string{"Security", "System"}

type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// ParseWevtutilXML converts concatenated <Event> elements into JSON lines,
// returning the lines and the highest EventRecordID seen.
func ParseWevtutilXML(data []byte) ([]Line, uint64) {
	var out []Line
	var maxID uint64
	dec := xml.NewDecoder(bytes.NewReader(append(append([]byte("<Events>"), data...), []byte("</Events>")...)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev winEvent
		if dec.DecodeElement(&ev, &se) != nil {
			continue
		}
		id, _ := strconv.Atoi(strings.TrimSpace(ev.System.EventID))
		d := map[string]string{}
		for i, x := range ev.EventData.Data {
			name := x.Name
			if name == "" {
				name = "param" + strconv.Itoa(i+1)
			}
			d[name] = x.Value
		}
		obj := map[string]any{
			"EventID": id, "TimeCreated": ev.System.TimeCreated.SystemTime, "Provider": ev.System.Provider.Name,
			"Channel": ev.System.Channel, "Computer": ev.System.Computer, "RecordID": ev.System.EventRecordID,
			"Message": "", "Data": d,
		}
		b, _ := json.Marshal(obj)
		out = append(out, Line{Source: "windows", Line: string(b), TS: ev.System.TimeCreated.SystemTime})
		if ev.System.EventRecordID > maxID {
			maxID = ev.System.EventRecordID
		}
	}
	return out, maxID
}

func wevtutil(ctx context.Context, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return exec.CommandContext(c, "wevtutil", args...).Output()
}

// RunWindowsEvents polls the configured channels.
func RunWindowsEvents(ctx context.Context, st *State, emit func(Line)) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		for _, ch := range winChannels {
			st.mu.Lock()
			last, known := st.WinRecord[ch]
			st.mu.Unlock()
			if !known {
				// first run: start from the newest record
				out, err := wevtutil(ctx, "qe", ch, "/c:1", "/rd:true", "/f:xml")
				if err != nil {
					continue
				}
				_, maxID := ParseWevtutilXML(out)
				st.mu.Lock()
				st.WinRecord[ch] = maxID
				st.mu.Unlock()
				continue
			}
			q := fmt.Sprintf("*[System[EventRecordID>%d]]", last)
			out, err := wevtutil(ctx, "qe", ch, "/q:"+q, "/c:2000", "/f:xml")
			if err != nil {
				continue
			}
			lines, maxID := ParseWevtutilXML(out)
			for _, l := range lines {
				emit(l)
			}
			if maxID > last {
				st.mu.Lock()
				st.WinRecord[ch] = maxID
				st.mu.Unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
