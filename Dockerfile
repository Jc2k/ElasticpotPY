FROM alpine:3.6 AS builder

RUN apk add --no-cache python3
RUN python3 -m venv /app

COPY requirements.txt /app/requirements.txt
RUN /app/bin/pip install -r /app/requirements.txt


FROM alpine:3.6

RUN \
  apk add --no-cache python3 && \
  addgroup elasticpot && \
  adduser -S -H -s /bin/false -D elasticpot

COPY --from=builder /app /app
COPY templates/ /app/src/templates/
COPY main.py /app/src/main.py

WORKDIR /app/src
EXPOSE 9200
USER elasticpot

CMD ["/app/bin/python", "/app/src/main.py"]
