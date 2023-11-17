#!/bin/bash

curl --json '{
  "tslSeqNr": 1,
  "certSerialNr": 874437375802245,
  "historyDeleteOption": "DELETE_NOTHING"
}' http://127.0.0.1:8080/info
