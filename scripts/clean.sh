#!/bin/bash
echo "Cleaning generated files..."
rm -rf *.pyc __pycache__ */__pycache__ .pytest_cache
rm -f *.out instr_*.c
rm -rf results/
rm -f bayzzer_results.json
echo "Clean complete."
