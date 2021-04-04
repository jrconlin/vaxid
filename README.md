
# Easy VAXID generation

Ben Adida [outlined](https://twitter.com/benadida/status/1378451455640625152) an interesting set of criteria for a SARS02/COVID-19 vaccination check system.

In short:
1) It should be open source
1) It should work on paper
1) It should be decentralized
1) It should ensure privacy

A lot of those align fairly well with Martin Thomson's work on [VAPID](https://tools.ietf.org/html/rfc8292).

This minimal library contains the minimal set of functions you need to
generate a VAPID key set and get the headers you'll need to sign a
WebPush subscription update.

VAPID is a voluntary standard for WebPush subscription providers
(sites that send WebPush updates to remote customers) to self-identify
to Push Servers (the servers that convey the push notifications).

The VAPID "claims" are a set of JSON keys and values. Vaxid alters the set of fields.

At a minimum a Vaxid claim set should look like:
```
{
    "nam": "Bullwinkle J Moose",    /* The patient's name */
    "idt": "2021-04-01",            /* Patient innoculation date */
    "ilc": "UCSF_Parnassus",        /* Innoculation location ID */
    "itp": "CA_Drivers",            /* Patient provided ID type
                                       e.g Drivers License, last 4 SS,
                                       PIN, etc.
                                    */
    "pid": "B012345678"             /* Patient provided ID value */
}
```
Additional fields may be included.

the ILC would provide a lookup for the innoculation provider for later confirmation
of the public key. Ideally the ID would be something like a reasonably readable ID
(stock symbol, hospital name, charity ID, etc) that could be provided as a distributed,
public list for verification systems to use. The list would also include a URL to the
Public Key so that the signature key can be matched and verified. An alternative would
be to index off of the public key directly, but that's less readable.

The resulting string could then be encoded into a QR code which can be printed or displayed,
scanned by a local device, which can then do either a quick local proof, or can do a
deeper verification by matching the public key against the published one. (Those keys can
be cached locally, providing for quicker, future updates.)

For example, the above encoded info would look like:
![Sample Image](img/sample.svg)

For this demo application, claims should be stored in a JSON compatible file. In the examples
below, we've stored the claims into a file named `claims.json`.

Vaxid can either be installed as a library or used as a stand along
app, `bin/vaxid`.

## App Installation

You'll need `python virtualenv` Run that in the current directory.

Then run
```
bin/pip install -r requirements.txt

bin/python setup.py install
```
## App Usage

Run by itself, `bin/vaxid` will check and optionally create the
public_key.pem and private_key.pem files.

`bin/vaxid --gen` can be used to generate a new set of public and
private key PEM files. These will overwrite the contents of
`private_key.pem` and `public_key.pem`.

`bin/vaxid --sign claims.json` will generate a set of HTTP headers
from a JSON formatted claims file. A sample `claims.json` is included
with this distribution.

`bin/vaxid --sign claims.json --json` will output the headers in
JSON format, which may be useful for other programs.

`bin/vaxid --verifyKey` will return the
verification key value you can use to make a restricted
endpoint. See
https://developer.mozilla.org/en-US/docs/Web/API/PushManager/subscribe
for more details. Be aware that this value is tied to the generated
public/private key. If you remove or generate a new key, any
restricted URL you've previously generated will need to be
reallocated. Please note that some User Agents may require you [to
decode this string into a Uint8Array](https://github.com/GoogleChrome/push-notifications/blob/master/app/scripts/main.js).

See `bin/vaxid -h` for all options and commands.
