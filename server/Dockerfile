FROM python:3.12-slim
RUN useradd --system --home /var/lib/sams --create-home sams
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir '.[ai]'
USER sams
ENV SAMS_DATA_DIR=/var/lib/sams
VOLUME ["/var/lib/sams"]
EXPOSE 8443 5514/udp 5514/tcp
ENTRYPOINT ["sams"]
CMD ["server", "--host", "0.0.0.0", "--port", "8443"]
