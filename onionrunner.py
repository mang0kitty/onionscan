import time
import sys
import subprocess
import random
import os
import json
import codecs
from threading import Event
from threading import Timer
from stem import Signal
from stem.control import Controller

onions = []
session_onions = []

# Event object to jelp coordinate two threads that will be executing
identity_lock = Event()
# set the event object first so that by default the main thread will execute later.
identity_lock.set()

#
# Grab the list of onions from our master file
#


def get_onion_list():
    # open the master list
    if os.path.exists("onion_master_list.txt"):
        with open("onion_master_list.txt", "rb") as fd:
            stored_onions = fd.read().splitlines()
    else:
        print("[!] No onion master list. Download it!")
        sys.exit(0)

    print("[*] Total onions for scanning: %d" % len(stored_onions))
    return stored_onions

#
#  Stores an onion in our master list of onions.
#


def store_onion():
    print("[++] Storing %s in master list. " % onion)

    with codecs.open("onion_master_list.txt", "ab", encoding="utf8") as fd:
        fd.write("%s\n" % onion)
    return

#
# Runs onion scan as a child process
#


def run_onionscan(onion):
    # onion is the address of our hidden service
    print("[*] Onionscanning %s" % onion)
    # fire up onnionscan
    process = subprocess.Popen(["onionscan", "--webport=0", "--jsonReport",
                                "--simpleReport=false", "%s" % onion], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # start the timer and let it run for 5 minutes
    process_timer = Timer(300, handle_timeout, args=[process, onion])
    process_timer.start()

    # wait for the onion scan
    stdout = process.communicate()[0]

    # if we received valid results so we can kill the timer
    if process_timer.is_alive():
        process_timer.cancel()
        return stdout
    print("[!!!] Process timed out!")

    return None

#
# Handle a timeout from the onionsan process
#


def handle_timeout(process, onion):
    global session_onions
    global identity_lock

    # halt the main thread while we grab a new identity
    identity_lock.clear()

    # kill the onion process
    try:
        process.kill()
        print("[!!!] Killed the onionscan process.")
    except:
        pass
    # Now we switch TOR identities to make sure we have a good connection
    with Controller.from_port(port=9051) as torcontrol:
        # authenticate to our local TOR controller
        torcontrol.authenticate("PythonRocks")

        # send the signal for a new identity
        torcontrol.signal(Signal.NEWNYM)

        # wait for the new identity to be initialized
        time.sleep(torcontrol.get_newnym_wait())

        print("[!!!] Switched TOR identities.")

    # push the onion back on to the list
    session_onions.append(onion)
    random.shuffle(session_onions)

    # allow the main thread to resume executing
    identity_lock.set()

    return


#
# Processes the JSON result from onionscan.
#
def process_results(onion, json_response):
    global onions
    global session_onions

    # create our output folder is necessary
    if not os.path.exists("onionscan_results"):
        os.mkdir("onionscan_results")

    # write out the JSON results of the scan
    with open("%s/%s.json" % ("onionscan_results", onion), "wb") as fd:
        fd.write(json_response)

    # look for additional .onion domains to add to our scan list
    scan_result = u"%s" % json_response.decode("utf8")
    scan_result = json.loads(scan_result)

    if scan_result['identifierReport']['linkedOnions'] is not None:
        add_new_onions(scan_result['identifierReport']['linkedOnions'])

    if scan_result['identifierReport']['relatedOnionDomains'] is not None:
        add_new_onions(scan_result['identifierReport']['relatedOnionDomains'])

    if scan_result['identifierReport']['relatedOnionServices'] is not None:
        add_new_onions(scan_result['identifierReport']['relatedOnionServices'])

        return

#
# Handle new onions.
#


def add_new_onions(new_onion_list):

    global onions
    global session_onions

    for linked_onion in new_onion_list:

        if linked_onion not in onions and linked_onion.endswith(".onion"):

            print("[++] Discovered new .onion => %s" % linked_onion)

            onions.append(linked_onion)
            session_onions.append(linked_onion)
            random.shuffle(session_onions)
            store_onion(linked_onion)

    return


 # get a list of onions to process
onions = get_onion_list()

# randomize the list
random.shuffle(onions)
session_onions = [o.decode("utf8") for o in onions]
count = 0

while count < len(onions):
    # if the event is cleared we will halt here otherwise continue executing
    identity_lock.wait()

    # grab a new onion to scan
    print("[*] Running % d of % d. " % (count, len(onions)))
    onion = session_onions.pop()

    # test if we have already retrieved results for this onion
    if os.path.exists("onionscan_results/%s.json" % onion):
        print("[!] Already retrieved %s. Skipping. " % onion)
        count += 1

        continue

    # run the onion scan
    results = run_onionscan(onion)

    # process the results
    if results is not None:
        if len(results):
            process_results(onion, results)

    count += 1
