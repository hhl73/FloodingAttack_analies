import numpy as np
def safe_float(number):
    try:
        return float(number)
    except:
        return None
def Z_ScoreNormalization(x):  #该函数没用
    x = (x - x.mean()) / x.std();
    return x;

def loaddataset():
    fp = open("attack.txt")
    # 存放数据
    dataset = []
    # 存放标签
    labelset = []
    B = np.zeros((143+200, 1),dtype=int)
    A = np.zeros((143+200, 5), dtype=float)
    row = 0
    for i in fp.readlines():
        #a = i.strip().split()
        a = i.strip('\n').split('\t')
        # 每个数据行的最后一个是标签
        #labelset.append(a[- 1])
        b = int(a[6])
        a = list(map(safe_float, a[1:6])) #转为float
        A[row] = a
        B[row] = b
        row += 1
        if row == 200:
            break
        #dataset.append(a)
    fp.close()
    #print(dataset)
    fp = open("no_attack.txt")
    for i in fp.readlines():
        #a = i.strip().split()
        a = i.strip('\n').split('\t')
        # 每个数据行的最后一个是标签
        #labelset.append(a[- 1])
        b = int(a[6])
        a = list(map(safe_float, a[1:6])) #转为float
        A[row] = a
        B[row] = b
        row += 1
        if row == B.shape[0]:
            break
    fp.close()
    # for i in range(13):
    #    A[i] = Z_ScoreNormalization(A[i])  # 标准化数据消除量纲
    permutation = np.random.permutation(B.shape[0])
    shuffled_dataset = A[permutation]
    shuffled_labels = B[permutation]
    labelset = shuffled_labels.tolist()
    dataset = shuffled_dataset.tolist()
    return dataset, labelset



# x为输入层神经元个数，y为隐层神经元个数，z输出层神经元个数
def parameter_initialization(x, y, z):
    # 隐层阈值
    value1 = np.random.randint(-5, 5, (1, y)).astype(np.float64)

    # 输出层阈值
    value2 = np.random.randint(-5, 5, (1, z)).astype(np.float64)

    # 输入层与隐层的连接权重
    weight1 = np.random.randint(-5, 5, (x, y)).astype(np.float64)

    # 隐层与输出层的连接权重
    weight2 = np.random.randint(-5, 5, (y, z)).astype(np.float64)

    return weight1, weight2, value1, value2

'''
def sigmoid(inx):
    hang = np.size(inx,0)
    lie = np.size(inx,1)
    A = np.zeros((hang,lie))
    print(hang,lie)
    for i in range(hang):
        for j in range(lie):
            if (inx[i][j] > 0).all:      #对sigmoid函数的优化，避免了出现极大的数据溢出
                A[i][j] = 1.0/(1+ np.exp(-inx[i][j]))
            else:
                A[i][j] = np.exp(inx[i][j])/(1+ np.exp(inx[i][j]))
    return A
'''
def sigmoid(z):
	return 1 / (1 + np.exp(-z))



'''
weight1:输入层与隐层的连接权重
weight2:隐层与输出层的连接权重
value1:隐层阈值
value2:输出层阈值
'''


def trainning(dataset, labelset, weight1, weight2, value1, value2):
    # x为步长
    x = 0.01
    for i in range(len(dataset)):
        # 输入数据
        inputset = np.mat(dataset[i]).astype(np.float64)
        # 数据标签
        outputset = np.mat(labelset[i]).astype(np.float64)
        # 隐层输入
        input1 = np.dot(inputset, weight1).astype(np.float64)
        # 隐层输出
        output2 = sigmoid(input1 - value1).astype(np.float64)
        # 输出层输入
        input2 = np.dot(output2, weight2).astype(np.float64)
        # 输出层输出
        output3 = sigmoid(input2 - value2).astype(np.float64)

        # 更新公式由矩阵运算表示
        a = np.multiply(output3, 1 - output3)
        g = np.multiply(a, outputset - output3)
        b = np.dot(g, np.transpose(weight2))
        c = np.multiply(output2, 1 - output2)
        e = np.multiply(b, c)

        value1_change = -x * e
        value2_change = -x * g
        weight1_change = x * np.dot(np.transpose(inputset), e)
        weight2_change = x * np.dot(np.transpose(output2), g)

        # 更新参数
        value1 += value1_change
        value2 += value2_change
        weight1 += weight1_change
        weight2 += weight2_change
    return weight1, weight2, value1, value2


def testing(dataset, labelset, weight1, weight2, value1, value2):
    # 记录预测正确的个数
    rightcount = 0
    for i in range(len(dataset)):
        # 计算每一个样例通过该神经网路后的预测值
        inputset = np.mat(dataset[i]).astype(np.float64)
        outputset = np.mat(labelset[i]).astype(np.float64)
        output2 = sigmoid(np.dot(inputset, weight1) - value1)
        output3 = sigmoid(np.dot(output2, weight2) - value2)

        # 确定其预测标签
        if output3 < 0.5:
            flag = 0
        else:
            flag = 1

        #flag = predict(dataset[i],labelset[i])

        if labelset[i][0] == flag:
            rightcount += 1
        # 输出预测结果
        print("预测为%d   实际为%d" % (flag, labelset[i][0]))
    # 返回正确率
    return rightcount / len(dataset)

def predict(data,label):
    print(type(data))
    weight1 = np.array([[-6.34149440e-08, 3.11250139e+00, 3.96471144e+00,-1.99778064e+00,3.67359581e+00],
                        [-1.00000008e+00, -3.41899938e+00,  1.96495452e+00, -4.99947778e+00,2.22411776e+00],
                        [9.99999914e-01, -2.41925782e+00, 9.61929690e-01, -2.99947778e+00,-4.76308092e+00],
                        [3.99999966e+00, 4.08660444e+00, -4.03711621e+00, 1.21324123e-02,-1.87253784e+00],
                        [1.99999825e+00, 4.58100062e+00,-1.15372830e+00,-4.99947778e+00,2.72964996e-01]])
    weight2 = np.array([[ 3.4481516 ],
                        [ 1.62237529],
                        [ 0.72202415],
                        [ 1.95391195],
                        [-5.72600222]])
    value1 = np.array([[-4.99853279,-5.11188852,-0.95268736,-0.97690434,-4.9829566 ]])
    value2 = np.array([[2.55228248]])
    inputset = np.mat(data).astype(np.float64)
    outputset = np.mat(label).astype(np.float64)
    output2 = sigmoid(np.dot(inputset, weight1) - value1)
    output3 = sigmoid(np.dot(output2, weight2) - value2)
    if output3 < 0.5:
        flag = 0
    else:
        flag = 1
    #print(flag)
    return flag

if __name__ == '__main__':
    dataset, labelset = loaddataset()
    weight1, weight2, value1, value2 = parameter_initialization(len(dataset[0]), len(dataset[0]), 1)
    for i in range(1):
        print('round:%d'%i)
        weight1, weight2, value1, value2 = trainning(dataset[0:300], labelset[0:300], weight1, weight2, value1, value2)
    print(weight1, weight2, value1, value2)
    rate = testing(dataset[300:-1], labelset[300:-1], weight1, weight2, value1, value2)
    print("正确率为%f" % (rate))
