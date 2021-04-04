# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import os
import json

from cryptography.hazmat.primitives import serialization
import qrcode

from vaxid import Vaxid, b64urlencode


def prompt(prompt):
    # Not sure why, but python3 throws and exception if you try to
    # monkeypatch for this. It's ugly, but this seems to play nicer.
    try:
        return input(prompt)
    except NameError:
        return raw_input(prompt)  # noqa: F821


def main():
    parser = argparse.ArgumentParser(description="VAXID tool")
    parser.add_argument('--sign', '-s', help='claims file to sign')
    parser.add_argument('--gen', '-g', help='generate new key pairs',
                        default=False, action="store_true")
    parser.add_argument('--json',  help="dump as json",
                        default=False, action="store_true")
    parser.add_argument('--no-strict', help='Do not be strict about "sub"',
                        default=False, action="store_true")
    parser.add_argument('--applicationServerKey',
                        help="show applicationServerKey value",
                        default=False, action="store_true")
    args = parser.parse_args()

    # Added to solve 2.7 => 3.* incompatibility
    if args.gen or not os.path.exists('private_key.pem'):
        if not args.gen:
            print("No private_key.pem file found.")
            answer = None
            while answer not in ['y', 'n']:
                answer = prompt("Do you want me to create one for you? (Y/n)")
                if not answer:
                    answer = 'y'
                answer = answer.lower()[0]
                if answer == 'n':
                    print("Sorry, can't do much for you then.")
                    exit(1)
        vaxid = Vaxid(conf=args)
        vaxid.generate_keys()
        print("Generating private_key.pem")
        vaxid.save_key('private_key.pem')
        print("Generating public_key.pem")
        vaxid.save_public_key('public_key.pem')
    vaxid = Vaxid.from_file('private_key.pem')
    claim_file = args.sign
    result = []
    if args.applicationServerKey:
        raw_pub = vaxid.public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
        print("Application Server Key = {}\n\n".format(
            b64urlencode(raw_pub)))
    if claim_file:
        if not os.path.exists(claim_file):
            print("No {} file found.".format(claim_file))
            print("""
The claims file should be a JSON formatted file that holds the
information that describes the patient.
""")
            exit(1)
        try:
            claims = json.loads(open(claim_file).read())
            result.append(vaxid.sign(claims))
        except Exception as exc:
            print("Crap, something went wrong: {}".format(repr(exc)))
            raise exc
        if args.json:
            print(json.dumps(result))
            return
        print("Encode the following...:\n")
        for value in result:
            print("{}\n".format(value))
            #qr = qrcode.QRCode()
            #qr.add_data(value)
            #qr.make()
            #img = qr.make_image()
            #with open("qr_code.png", "x") as file:
            #    img.save(file)
            #    print("Written to qr_code.png")

        print("\n")


if __name__ == '__main__':
    main()
