#!/bin/bash

unset JWT_HEADER
unset JWT_PAYLOAD
unset JWT_SIGNATURE
for i in {1..99}; do
unset "DISCLOSURE_$i"
done

