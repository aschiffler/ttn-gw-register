FROM golang:alpine3.19

COPY ./app .
RUN go build main.go && chmod 755 main

CMD [ "./main"]
