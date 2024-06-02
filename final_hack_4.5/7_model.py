#This file trains model, selects best model, seclects different versions of selected model and saves as best_rf_model.joblib and plots all graphs
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import friedmanchisquare
import scikit_posthocs as sp
from sklearn.preprocessing import StandardScaler
# Function to clean data
def clean_data(df):
    df = df.apply(pd.to_numeric, errors='coerce')
    df = df.fillna(0)
    return df

# Load and prepare the dataset
phishing_data = pd.read_csv('original_new_phish_25k.csv', dtype=str, low_memory=False)
legitimate_data = pd.read_csv('legit_data.csv', dtype=str, low_memory=False)
phishing_data['Label'] = 1
legitimate_data['Label'] = 0
dataset = pd.concat([phishing_data, legitimate_data])
dataset = dataset.drop(['url', 'NonStdPort', 'GoogleIndex', 'double_slash_redirecting', 'https_token'], axis=1)
dataset = clean_data(dataset)
X = dataset.drop('Label', axis=1)
y = dataset['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Define classifiers
classifiers = {
    'Naive Bayes': GaussianNB(),
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'AdaBoost': AdaBoostClassifier(n_estimators=100, random_state=42),
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'Multilayer Perceptron': MLPClassifier(max_iter=300, random_state=42),
    'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=5),
    'Support Vector Machine': SVC(kernel='linear', probability=True, random_state=42, max_iter=5000)
}

# Train and evaluate initial classifiers
results = []
for name, clf in classifiers.items():
    try:
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        results.append((name, accuracy))
        print(f"{name} Accuracy: {accuracy:.4f}")
    except Exception as e:
        print(f"Error training {name}: {e}")

# Convert results to DataFrame
results_df = pd.DataFrame(results, columns=['Classifier', 'Accuracy'])

# Perform Bonferroni-Dunn test
try:
    dunn_results = sp.posthoc_dunn(results_df, val_col='Accuracy', group_col='Classifier', p_adjust='bonferroni')
    print(dunn_results)
except Exception as e:
    print(f"Error in Bonferroni-Dunn test: {e}")

# Plot the accuracies of classifiers
plt.figure(figsize=(10, 6))
sns.barplot(x='Classifier', y='Accuracy', data=results_df, palette='viridis')
plt.title('Classifier Accuracies')
plt.xticks(rotation=45)
plt.savefig('graphs/classifier_accuracies.png')
plt.show()

# Heatmap of pairwise comparison (Bonferroni-Dunn test) for initial classifiers
plt.figure(figsize=(12, 8))
sns.heatmap(dunn_results, annot=True, cmap='coolwarm', cbar=True, fmt=".2f")
plt.title('Bonferroni-Dunn Test Results for Initial Classifiers')
plt.savefig('graphs/dunn_test_initial_classifiers.png')
plt.show()

# Box plot of accuracy distributions for initial classifiers
plt.figure(figsize=(14, 7))
sns.boxplot(x='Classifier', y='Accuracy', data=results_df, palette='viridis')
plt.title('Accuracy Distributions of Initial Classifiers')
plt.xticks(rotation=45)
plt.savefig('graphs/boxplot_initial_classifiers.png')
plt.show()

# Save the best initial model
best_model_name = results_df.loc[results_df['Accuracy'].idxmax(), 'Classifier']
best_model = classifiers[best_model_name]
best_accuracy = results_df.loc[results_df['Classifier'] == best_model_name, 'Accuracy'].values[0]

model_filename = 'best_initial_model.joblib'
joblib.dump(best_model, model_filename)
print(f"Best initial model saved as {model_filename} with accuracy {best_accuracy:.4f}")

# Define 11 different versions of the Random Forest
rf_versions = {
    'RF_10_trees': RandomForestClassifier(n_estimators=10, random_state=42),
    'RF_50_trees': RandomForestClassifier(n_estimators=50, random_state=42),
    'RF_100_trees': RandomForestClassifier(n_estimators=100, random_state=42),
    'RF_200_trees': RandomForestClassifier(n_estimators=200, random_state=42),
    'RF_max_depth_10': RandomForestClassifier(max_depth=10, n_estimators=100, random_state=42),
    'RF_max_depth_20': RandomForestClassifier(max_depth=20, n_estimators=100, random_state=42),
    'RF_max_features_sqrt': RandomForestClassifier(max_features='sqrt', n_estimators=100, random_state=42),
    'RF_max_features_log2': RandomForestClassifier(max_features='log2', n_estimators=100, random_state=42),
    'RF_min_samples_split_2': RandomForestClassifier(min_samples_split=2, n_estimators=100, random_state=42),
    'RF_min_samples_split_5': RandomForestClassifier(min_samples_split=5, n_estimators=100, random_state=42)
}

# Train and evaluate the different versions of the Random Forest
rf_results = []
for name, clf in rf_versions.items():
    try:
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        rf_results.append((name, accuracy))
        print(f"{name} Accuracy: {accuracy:.4f}")
    except Exception as e:
        print(f"Error training {name}: {e}")

# Convert Random Forest results to DataFrame
rf_results_df = pd.DataFrame(rf_results, columns=['Version', 'Accuracy'])

# Perform Bonferroni-Dunn test on Random Forest versions
try:
    rf_dunn_results = sp.posthoc_dunn(rf_results_df, val_col='Accuracy', group_col='Version', p_adjust='bonferroni')
    print(rf_dunn_results)
except Exception as e:
    print(f"Error in Bonferroni-Dunn test for RF versions: {e}")

# Plot the accuracies of Random Forest versions
plt.figure(figsize=(12, 8))
sns.barplot(x='Version', y='Accuracy', data=rf_results_df, palette='viridis')
plt.title('Random Forest Versions Accuracies')
plt.xticks(rotation=45)
plt.savefig('graphs/rf_versions_accuracies.png')
plt.show()

# Heatmap of pairwise comparison (Bonferroni-Dunn test) for Random Forest versions
plt.figure(figsize=(14, 10))
sns.heatmap(rf_dunn_results, annot=True, cmap='coolwarm', cbar=True, fmt=".2f")
plt.title('Bonferroni-Dunn Test Results for Random Forest Versions')
plt.savefig('graphs/dunn_test_rf_versions.png')
plt.show()

# Box plot of accuracy distributions for Random Forest versions
plt.figure(figsize=(14, 8))
sns.boxplot(x='Version', y='Accuracy', data=rf_results_df, palette='viridis')
plt.title('Accuracy Distributions of Random Forest Versions')
plt.xticks(rotation=45)
plt.savefig('graphs/boxplot_rf_versions.png')
plt.show()

# Line plot of accuracies of Random Forest versions
plt.figure(figsize=(12, 8))
sns.lineplot(x='Version', y='Accuracy', data=rf_results_df, marker='o', palette='viridis')
plt.title('Line Plot of Random Forest Versions Accuracies')
plt.xticks(rotation=45)
plt.savefig('graphs/lineplot_rf_versions.png')
plt.show()

# Save the best Random Forest version
best_rf_model_name = rf_results_df.loc[rf_results_df['Accuracy'].idxmax(), 'Version']
best_rf_model = rf_versions[best_rf_model_name]
best_rf_accuracy = rf_results_df.loc[rf_results_df['Version'] == best_rf_model_name, 'Accuracy'].values[0]

rf_model_filename = 'best_rf_model.joblib'
joblib.dump(best_rf_model, rf_model_filename)
print(f"Best Random Forest model saved as {rf_model_filename} with accuracy {best_rf_accuracy:.4f}")

# Additional Plots
# Scatter plot of accuracies of different classifiers
plt.figure(figsize=(10, 8))
sns.scatterplot(x='Classifier', y='Accuracy', data=results_df, hue='Accuracy', palette='viridis', s=100)
plt.title('Scatter Plot of Classifier Accuracies')
plt.xticks(rotation=45)
plt.savefig('graphs/scatter_plot_initial_classifiers.png')
plt.show()

# Scatter plot of accuracies of Random Forest versions
plt.figure(figsize=(12, 8))
sns.scatterplot(x='Version', y='Accuracy', data=rf_results_df, hue='Accuracy', palette='viridis', s=100)
plt.title('Scatter Plot of Random Forest Versions Accuracies')
plt.xticks(rotation=45)
plt.savefig('graphs/scatter_plot_rf_versions.png')
plt.show()

# Plot the accuracies of Random Forest versions
plt.figure(figsize=(12, 8))
sns.barplot(x='Version', y='Accuracy', data=rf_results_df, palette='viridis')
plt.title('Random Forest Versions Accuracies')
plt.xticks(rotation=45)
plt.show()