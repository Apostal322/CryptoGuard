"""Historical incident replay: does a detector warn before a known harmful transaction, using
only data that existed at the time? Manifests hold publicly sourced ground truth; fixtures
hold recorded chain data; the engine replays them offline and deterministically."""
