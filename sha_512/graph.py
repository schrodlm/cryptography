import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit

# plotting the data
collisions = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
times =  np.array([5, 6, 8, 16, 24, 48, 91, 168, 330, 759, 1580, 2939, 5322, 10399, 21953, 45278])
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
plt.ylabel("Time [microseconds]")
plt.show()


# Save the plot to a file
plt.savefig('plot.png')
