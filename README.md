# Jepsen Tests for Tendermint

[Jepsen](https://jepsen.io/) tests for [Tendermint](https://github.com/tendermint/tendermint).

The initial test suite was written back in Sept. 2017 in the attempt to verify
Tendermint safety guarantees. No significant issues were found: "Tendermint
appears to satisfy its safety guarantees". You can read [the full report
](https://jepsen.io/analyses/tendermint-0-10-2) for more details.

This repository is a fork of [the main Jepsen
repository](https://github.com/jepsen-io/jepsen). The initial test suite was
copied from [jepsen-io/tendermint
repository](https://github.com/jepsen-io/tendermint).

## Quickstart

Assuming you have [docker-compose](https://github.com/docker/compose) set up
already, run:

```
cd docker && bin/up
```

In another terminal, run:

```
cd docker && bin/console
```

Once console is up, run:

```
root@control:/jepsen# cd tendermint && lein run test
```

The output should look something like this:

```
       {:process 85,
        :type :invoke,
        :f :read,
        :value nil,
        :index 110,
        :time 53268946400}]}),
    :analyzer :linear,
    :final-paths ()}},
  :failures []},
 :valid? true}


Everything looks good!
```

Please refer to [docker README](./docker/README.md) for additional docker
options and [tendermint README](./tendermint/README.md) for more test options.

## Updating Jepsen

Add an upstream remote (one time):

```
git remote add upstream https://github.com/jepsen-io/jepsen.git
```

Fetch the changes (if any) and rebase:

```
git fetch upstream
git rebase upstream/master
```

## License

Copyright © 2017 Jepsen, LLC

Distributed under the Apache Public License 2.0.
