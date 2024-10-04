# DDoS Detection Using Machine Learning

## Project Overview

This project focuses on developing a **machine learning model** for classifying network traffic with the aim of distinguishing between **benign traffic** and **DDoS (Distributed Denial of Service) attacks**. The primary goal is to build a model capable of detecting these types of traffic using a dataset that includes both legitimate and DDoS traffic.

The project is organized into several sections, with each section addressing a key component of the machine learning process, from data exploration and pre-processing to model training and clustering analysis.

## Project Structure

The project is divided into the following sections, each detailed in separate Jupyter notebooks:

1. **Data Exploration and Pre-processing**:
   - This section involves understanding the dataset using **statistical analysis** and **visualization techniques**.
   - Tasks include feature normalization, removal of highly correlated features, and handling missing data to improve the model's performance.
   - This phase is crucial for addressing the **curse of dimensionality** and preparing the data for machine learning models.
   
   *Notebook:* [ML4N_Project_Group9_Section_1.ipynb](Code/ML4N_Project_Group9_Section_1.ipynb)

2. **Supervised Learning – Classification**:
   - Various **supervised learning models** are trained and evaluated to identify the most effective approach for detecting and classifying network traffic.
   - Models include **logistic regression**, **decision trees**, **random forests**, **support vector machines (SVM)**, and more.
   - The notebook includes **hyperparameter tuning** and performance analysis (e.g., accuracy, precision, recall, F1-score, AUC).
   
   *Notebook:* [ML4N_Project_Group9_Section_2.ipynb](Code/ML4N_Project_Group9_Section_2.ipynb)

3. **Unsupervised Learning – Clustering**:
   - This section explores **clustering algorithms** such as **K-Means** and **DBSCAN** to uncover patterns in the network traffic data without labeled examples.
   - Clustering helps identify natural groupings of data, which may reveal previously undetected patterns related to DDoS attacks.
   
   *Notebook:* [ML4N_Project_Group9_Section_3.ipynb](Code/ML4N_Project_Group9_Section_3.ipynb)

4. **Cluster Explainability and Analysis**:
   - After applying the clustering algorithms, this section focuses on analyzing the resulting clusters, including the **distribution** of traffic types, feature importance, and other characteristics.
   - The explainability of clusters is key to understanding the nature of the identified traffic patterns, and conclusions are drawn about **cybersecurity threats**.
   
   *Notebook:* [ML4N_Project_Group9_Section_4_1.ipynb](Code/ML4N_Project_Group9_Section_4_1.ipynb)
   
   *Notebook:* [ML4N_Project_Group9_Section_4_2.ipynb](Code/ML4N_Project_Group9_Section_4_2.ipynb)

## Dataset

The dataset used in this project was provided by the instructors. It contains a variety of network packet flow samples, including both **benign traffic** and **data related to DDoS attack scenarios**. The dataset has been curated to ensure an **accurate and balanced representation** of the different types of traffic the model will encounter in real-world scenarios.

   *Dataset:* [ddos_dataset.csv](Code/ddos_dataset.csv)
