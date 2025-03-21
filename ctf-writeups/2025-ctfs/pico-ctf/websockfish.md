# WebSockFish

## Homepage

<figure><img src="../../../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

The challenge description hints about reading the script, how data is been sent to & fro.

It's using WebSockFish, after a quick google search I got to know that it's vulnerable to Buffer Overflow (since it'a a WASM based lib)\
Also there are only few combination moves in chess, what if we send a number that's not a possible one.

Hence I thought sending a high value can cause overflow & the server will send out the flag.

## Flag

<figure><img src="../../../.gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

### Resources

[https://github.com/official-stockfish/Stockfish/pull/4558](https://github.com/official-stockfish/Stockfish/pull/4558)

\_\_\_\_\_\_\_\_heapbytes' still pwning
