# timeshifter

Transmissions over time based covert channels across a network

We created a system in order to transmit and receive data by modifying the time intervals between packets. 


# setup

On Ubuntu/Debian:

```
sudo apt-get install libnetfilter-queue-dev
```

On Arch:

```
sudo pacman -S libnetfilter_queue
```

# example

Setup iptables rules based on the example_rules_single_computer.sh file provided.

*N.B. once you’ve activated these iptables rules, then packets will not be sent out from the computer until you run the program below.*

Run the transmitter using:

```
echo "helloworld" | ./timeshifter 0 2000 3000
```

Run the reciever using:         

```
./timeshifter 1 2000 3000
```

Then ping a remote host, the transmitting packet's intervals will be modulated with your data, the pong replies will then be decoded by the reciever.

Please see https://www.anfractuosity.com/projects/timeshifter/ for additional explaination
