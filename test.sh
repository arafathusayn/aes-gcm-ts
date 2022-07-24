#!/bin/bash

rm -f coverage/*

deno test --coverage=coverage && deno coverage coverage/
