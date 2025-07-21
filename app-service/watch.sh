#!/bin/sh

cargo watch --clear --exec=run --quiet --watch=assets/ --watch=src/ --watch=templates/
