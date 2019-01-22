The nessus scanner is not sophisticated enough to do useful scanning
of the databases.

# Example Run

echo "fsdb-36" | python ../scng-nessus/db_audit.py --set-log-level=20 --fuser nessus --fields-ssh-id /home/awfuller/.ssh/id_nessus --out-file /tmp/test.csv

