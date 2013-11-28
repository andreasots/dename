How to install/use:

* Install an up-to-date version of PostgreSQL
* Install an up-to-date version of golang (>= 1.1.2)
* Set up your $GOPATH, if you don't have it already:
    * Create a directory to hold go source code for your user, e.g. `$HOME/go`
    * Edit `~/.profile` to contain the following lines (change $HOME/go if you like): 

            export $GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$PATH

    * You'll have to log out and log in for this to take effect (or just set the variables manually).
* Run `go install github.com/andres-erbsen/dename`
* Create a DB user and a new database in PostgreSQL
*    Configure your `dename.cfg` 
* Run `dename`

How to test multiple instances on the same machine:
* Add an IP address for each instance, e.g.

        sudo ip addr add 11.22.33.44/30 dev lo:1
        sudo ip addr add 11.22.33.45/30 dev lo:2
        sudo ip addr add 11.22.33.46/30 dev lo:3

* Make a DB for each instance
* Make directories for all the instances
* In each directory, run `go run $GOPATH/src/github.com/andres-erbsen/sgp/keygen.go 2>sk | base64` and paste the output into the peer declarations in `dename.cfg`
* Copy the `dename.cfg` into each directory, changing the host IP and DB
* Run `dename` in each directory in parallel

