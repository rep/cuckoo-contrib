cuckoo-contrib
==============

Welcome to Mark's Cuckoo Supplement Shop!

![alt text](https://github.com/rep/cuckoo-contrib/raw/master/supplements.jpg "Cuckoo Contrib Supplements")

Products
--------

* cuckootables.sh

  We recommend to use VMs with a host-only network setup and then manual forwarding / routing to the Internet and other resources.
  This shell script serves as a starting point for your Cuckoo deployment.

* fakedns.py

  If you want to run a Cuckoo setup without Internet connectivity you can only get information about network activity by supplying the VM with fake resources to connect to.
  This Python script replies to DNS queries with a fixed IP that you specify. On that IP - may it be the Cuckoo machine or something else - you can then host fake services such as InetSim or setup custom services as needed.

* runit/run
* runit/log/run

  You should run Cuckoo in conjunction with a watchdog process that restarts it in case of failures / crashes. For this purpose we use "[runit](http://smarden.org/runit/)" on our setups and malwr.com. To do so as well, install runit and then copy the "runit" folder from this repository to `/etc/sv/cuckoo`. Make both `run` files executable and symlink to `/etc/service/cuckoo`:

 ```
 cp -r runit /etc/sv/cuckoo
 chmod +x /etc/sv/cuckoo/run /etc/sv/cuckoo/log/run
 ln -s /etc/sv/cuckoo /etc/service/cuckoo
 ```


