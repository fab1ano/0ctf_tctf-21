FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
 build-essential \
 pkg-config \
 python

RUN adduser --no-create-home --disabled-password --gecos "" ctf
WORKDIR /home/ctf
COPY --chown=root:ctf server.py tjs flag.txt flag_printer ./
RUN chown -R root:ctf ./
RUN sed -i "s/flag{XXXXXXXXXXXXXXXXXXXXXXXXXXXXX}/$(cat flag.txt)/g" flag_printer
RUN rm flag.txt

RUN chmod 750 ./ \
    && chmod 110 flag_printer \
    && chmod g+s tjs 

EXPOSE 8888
CMD ["./server.py"]