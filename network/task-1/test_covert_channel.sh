#!/bin/bash

case $1 in

    setup)
    docker network create --subnet=172.68.0.0/16 net-covert
    ;;

    start_server)
    docker build -t covert:latest .
    docker run --rm -it --name covert-server --network net-covert covert:latest python3 /app/server.py
    ;;

    start_client)
    docker build -t covert:latest .
    docker run --rm -it --name covert-client --network net-covert covert:latest python3 /app/client.py
    ;;

    cleanup)
    docker network rm net-covert
    ;;

esac