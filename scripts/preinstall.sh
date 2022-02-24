#!/bin/bash
set -e

if [ "$CI" != true ] ; then
  pre-commit install
fi