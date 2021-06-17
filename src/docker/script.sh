#!/bin/bash

echo "Running Prowler Scans - ISO 27001"
./prowler -g iso27001 -M json-asff -q -S -f eu-central-1 -r eu-central-1

echo "Running Prowler Scans - GDPR"
./prowler -g gdpr -M json-asff -q -S -f eu-central-1 -r eu-central-1

echo "Finished Security Sanity Scans"