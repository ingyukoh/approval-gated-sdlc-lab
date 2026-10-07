"""Versioned state; production demo uses conditional DynamoDB updates."""
import copy
import json
import os
import threading
import time


class Conflict(Exception):
    pass


class MemoryStore:
    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            return copy.deepcopy(self.rows.get(key))

    def put(self, key, value, expected):
        with self.lock:
            row = self.rows.get(key)
            if (row is None and expected != 0) or (row is not None and row['version'] != expected):
                raise Conflict('state_conflict')
            v = copy.deepcopy(value)
            v['version'] = expected + 1
            self.rows[key] = v
            return copy.deepcopy(v)

    def limit(self, key, maximum, ttl):
        with self.lock:
            row = self.rows.get(key, {'count': 0, 'expires_at': ttl})
            if row['count'] >= maximum:
                return False
            row['count'] += 1
            self.rows[key] = row
            return True


class DynamoStore:
    def __init__(self, table):
        import boto3
        self.client = boto3.client('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        self.table = table

    def get(self, key):
        row = self.client.get_item(TableName=self.table, Key={'pk': {'S': key}}, ConsistentRead=True).get('Item')
        return json.loads(row['payload']['S']) if row and 'payload' in row else None

    def put(self, key, value, expected):
        v = copy.deepcopy(value)
        v['version'] = expected + 1
        kw = {'TableName': self.table, 'Item': {'pk': {'S': key}, 'payload': {'S': json.dumps(v)},
              'version': {'N': str(v['version'])}, 'expires_at': {'N': str(int(time.time()) + 86400)}}}
        if expected == 0:
            kw['ConditionExpression'] = 'attribute_not_exists(pk)'
        else:
            kw.update(ConditionExpression='#v = :expected', ExpressionAttributeNames={'#v': 'version'},
                      ExpressionAttributeValues={':expected': {'N': str(expected)}})
        try:
            self.client.put_item(**kw)
        except self.client.exceptions.ConditionalCheckFailedException:
            raise Conflict('state_conflict') from None
        return v

    def limit(self, key, maximum, ttl):
        try:
            self.client.update_item(TableName=self.table, Key={'pk': {'S': key}},
                UpdateExpression='SET expires_at = :ttl ADD #c :one',
                ConditionExpression='attribute_not_exists(#c) OR #c < :maximum',
                ExpressionAttributeNames={'#c': 'counter'},
                ExpressionAttributeValues={':ttl': {'N': str(ttl)}, ':one': {'N': '1'}, ':maximum': {'N': str(maximum)}})
            return True
        except self.client.exceptions.ConditionalCheckFailedException:
            return False
