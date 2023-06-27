import os


def getFilenames(path):
    filenames = []
    for root, dirs, files in os.walk(path):
        for file in files:
            filenames.append(os.path.join(root, file))
    return filenames
