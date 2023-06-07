# Running the formatting providers for the project
# must be run in the poetry shell or using `poetry run`

# First isort(import formatter)
echo "\n---- Isort"
isort .

# black the formatter
echo "\n---- Black"
black .

# now flake8 for linting
echo "\n---- Flake8"
if [[ $(flake8) ]]; then
    flake8
else
    echo "No Errors were found."
fi

# and also mypy for static type checking
echo "\n---- MyPy"
mypy
