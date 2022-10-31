#!/bin/sh
# Testing script for CSE 545 Reflector Project
# Note that this needs a Linux kernel that supports network namespaces

sudo /bin/bash -c "make && [ -e ./reflector ] && [ -x ./reflector ]"

sudo ip netns add reflector
sudo ip netns exec reflector ip link add eth0-fake type veth peer name eth0-fake-2

sudo ip link add v-test type veth peer name v-ref


sudo ip link set v-ref netns reflector

sudo ip netns exec reflector ip link set lo up

sudo ifconfig v-test 10.0.0.1/24 up

sudo ip netns exec reflector ifconfig v-ref 10.0.0.2/24 up
sudo ip netns exec reflector ifconfig eth0-fake 192.168.1.2/24 up
sudo ip netns exec reflector ifconfig eth0-fake-2 192.168.10.1/24 up

sudo ip netns exec reflector ip route add default via 192.168.1.1

trap ' ' INT
echo "Going to run the reflector on the virtual interface v-ref (which is in the reflector network namespace), victim IP of 10.0.0.3, reflector IP of 10.0.0.4. "
echo "Once it's running, feel free to run tests such as pinging 10.0.0.3 from another terminal."
echo "To see the packets that you're sending from the attacker: sudo tcpdump -ni v-test"
echo "To see the packets that your reflector program is sending: sudo ip netns exec reflector tcpdump -ni v-ref"
echo "To debug what's going on in the reflector's network namespace, you can open a bash terminal with the following: sudo ip netns exec reflector /bin/bash"
echo "Control-C when you're done to kill your reflector and cleanup."
echo ""
sudo ip netns exec reflector ./reflector --interface v-ref --victim-ip 10.0.0.3 --victim-ethernet ff:b2:bb:ee:aa:8f --reflector-ip 10.0.0.4 --reflector-ethernet aa:11:86:99:88:8f

echo "Cleaning up"
sudo ip netns exec reflector ip link set lo down
sudo ip netns exec reflector ip link set eth0-fake down

sudo ip link del v-test

sudo ip netns del reflector
