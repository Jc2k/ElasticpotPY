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
COPY elasticpot /app/src/elasticpot

WORKDIR /app/src
EXPOSE 9200
USER elasticpot

ENV PYTHONUNBUFFERED 1

CMD ["/app/bin/gunicorn", "-b", "0.0.0.0:9200", "elasticpot.wsgi:application"]
