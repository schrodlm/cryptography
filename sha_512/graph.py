import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit
from PIL import Image

# plotting the data
collisions = np.array([3, 4, 5, 6, 7, 8])
times =  np.array([10, 20, 40, 100, 200, 400])
plt.plot(collisions, times, 'o', label='data')  #o=circle

# creating model
def model(x, a, b):
    return a * np.power(2, b*x)

# fitting the model
a, b = curve_fit(model, collisions, times)[0]
print("model: {} * 2^({}x)".format(a,b))

# plotting the model
modelx = np.linspace(1, np.max(collisions) ,100)
modely = model(modelx, a, b)
plt.plot(modelx, modely, label='model')

# full collision
print("Full collision time: ", model(512, a, b))

# show the plot
plt.legend(loc="upper left")
plt.xlabel("Number of collision bits")
plt.ylabel("Time")
plt.show()


# Save the plot to a file
plt.savefig('plot.png')
