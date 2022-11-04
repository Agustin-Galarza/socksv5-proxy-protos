FROM gcc:latest

WORKDIR /app

COPY . .

# RUN ls
RUN apt-get update && \
    apt-get -y install make &&\
    make clean &&\
    make all

CMD ["./run.sh"]