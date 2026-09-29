"""Reset consumer group offsets to latest for raw-logs topic to skip stale backlog."""
from kafka import KafkaConsumer
from kafka.admin import KafkaAdminClient
from kafka.structs import TopicPartition

BOOTSTRAP = "localhost:9092"
GROUPS_TO_RESET = [
    "ulpf-raw-storage",
    "ulpf",
    "ulpf-normalized-storage",
]

# Connect and list consumer groups
admin = KafkaAdminClient(bootstrap_servers=BOOTSTRAP)
groups = admin.list_consumer_groups()
print("Consumer groups:")
for g in groups.valid:
    print(f"  {g.group_id} state={g.state}")

# Reset each group to latest
for group_id in GROUPS_TO_RESET:
    try:
        consumer = KafkaConsumer(
            bootstrap_servers=BOOTSTRAP,
            group_id=group_id,
            enable_auto_commit=False,
            consumer_timeout_ms=1000,
        )
        tps = [tp for tp in consumer.assignment()]
        print(f"\nGroup {group_id}: {len(tps)} partitions assigned")
        for tp in tps:
            end = consumer.end_offsets([tp])[tp]
            consumer.seek(tp, end)
            print(f"  {tp} -> latest offset {end}")
        consumer.close()
    except Exception as exc:
        print(f"Group {group_id}: error {exc}")

print("\nDone. Reset complete.")