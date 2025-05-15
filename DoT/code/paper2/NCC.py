import numpy as np
from tqdm import tqdm
from rtree import index

def ts2nccVec(ts):
    pass

class NCCTree:


    def __init__(self, dim):
        self.dim = dim

        p = index.Property()
        p.dimension = self.dim
        idx = index.Index(properties=p)

        self.idx = idx
        self.pointIDX = 0
        self.points = {}


    def insert(self, point):
        cords = np.concatenate((point, point))
        self.idx.insert(self.pointIDX, cords)
        self.points[self.pointIDX] = point

        self.pointIDX += 1

    def knn(self, point, k):
        ids = list(self.idx.nearest(point, k))
        return [self.points[id] for id in ids]

    def ncc(self, query, k):
        P = self.knn(query, k)
        return [np.dot(query, p) for p in P]

# def sample_spherical(npoints, ndim):
#     vec = np.random.randn(ndim, npoints)
#     vec /= np.linalg.norm(vec, axis=0)
#     return vec.T

def main():
    num_ts = 100
    len_ts = 3000
    points = gen_ts(num_ts, len_ts)


    tree = NCCTree(len_ts)
    for p in tqdm(points):
        assert abs(1 - np.linalg.norm(p)) < 0.0001
        tree.insert(p)

    for p in tqdm(points):
        n = tree.ncc(p, 2)
        # print(n)
        assert(all(n[i] >= n[i + 1] for i in range(len(n) - 1)))

if __name__ == "__main__":
    main()
