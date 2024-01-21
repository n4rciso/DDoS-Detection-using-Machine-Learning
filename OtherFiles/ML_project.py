import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Carico il dataset
df = pd.read_csv('ddos.csv')
df.columns = df.columns.str.strip()

# Creo una mappa per mappare i valori di label (ultima feature) in numeri
unique_attack_types = df['label'].unique()
# Creo la mappa automaticamente assegnando un numero a ciascun tipo di attacco
attack_type_mapping = {attack_type: i for i, attack_type in enumerate(unique_attack_types)}
# La mappa sarà di questo tipo:
# {'ddos_dns': 0, 'benign': 1, 'ddos_ldap': 2, 'ddos_mssql': 3, 'ddos_netbios': 4,
# 'ddos_ntp': 5, 'ddos_snmp': 6, 'ddos_ssdp': 7, 'ddos_udp': 8, 'ddos_syn': 9, 'ddos_tftp': 10, 'ddos_udp_lag': 11}
df_numerical_label = df.replace({'label': attack_type_mapping})



# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# PUNTO 1: Produce different visualizations and statistical analysis both at the generic traffic level 
# (e.g., number of flows, etc.) and GT level. (e.g., distribution of features, GT class 
# characterization, ECDF of ports, flows, etc.)


# Visualizzazione 1: numero di flussi per ogni classe di attacco
plt.figure(figsize=(12,8))
sns.countplot(x="label", data=df)
plt.title("Distribuzione delle classi di attacco")
plt.xlabel("Classe di Attacco")
plt.ylabel("Numero di Flussi")
plt.show()


# Visualizzazione 2:  distribuzione della feature selezionata (in questo caso 'Flow Duration') 
# per ogni classe di attacco. È utile per identificare pattern o differenze nelle distribuzioni 
# delle feature tra le classi di attacco.
feature_to_plot = 'Flow Duration'
plt.figure(figsize=(12, 8))
sns.boxplot(x="label", y=feature_to_plot, data=df)
plt.title(f'Relazione tra {feature_to_plot} e classi di attacco')
plt.xlabel("Classe di Attacco")
plt.ylabel(f"{feature_to_plot}")
plt.show()


# Visualizzazione 3: istogramma della durata dei flussi, per avere idea di quanto siano tipicamente lunghi, ossia
# quanto siano frequenti i flussi di diversa durata
df['Flow Duration'].hist(bins=50)
plt.title('Distribuzione della durata del flusso')
plt.xlabel('Durata del flusso')
plt.ylabel('Frequenza')
plt.show()


# Visualizzazione 4: ECDF (Empirical Cumulative Distribution Function) della durata totale dei fwd packets (the total length, in bytes,
#  of the packets sent from the source to the destination), utile per capire come la maggior parte degli attacchi usino quasi al
# 100% la stessa dimensione dei pacchetti, mentre altri (tra tutti ddos_dns) usino pacchetti di dimensioni molto diverse e 
# variabili tra loro (MOTIVAZIONE:  Durante un attacco DDoS su DNS, gli attaccanti possono generare una varietà di query DNS, 
# ciascuna con requisiti diversi di lunghezza del pacchetto. Ad esempio, potrebbero essere inclusi nomi di dominio legittimi, 
# stringhe casuali o caratteri non validi per cercare di sfruttare le vulnerabilità nel server DNS di destinazione.
plt.figure(figsize=(12, 8))
sns.ecdfplot(x='Total Length of Fwd Packets', data=df, hue='label')
plt.title('ECDF di Total Length of Fwd Packets per classe GT')
plt.xlabel('Total Length of Fwd Packets')
plt.ylabel('Percentuale cumulativa')
plt.show()




# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# PUNTO 2: Generate additional features e.g., quantifying the traffic related to each flow on the
# basis of the previous analysis (e.g. avg, min, max, quantiles, etc.)




# Creo un elenco delle caratteristiche numeriche nel tuo dataset
numeric_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
# Raggrupo per label
df_grouped = df.groupby('label')
# Creo un dataframe vuoto per le nuove caratteristiche
df_new_features = pd.DataFrame()
# Calcolo le statistiche per ogni caratteristica numerica
for feature in numeric_features:
    feature_stats = df_grouped[feature].agg(['min','max','mean','std']).rename(columns={'min': feature + '_min', 'max': feature + '_max', 'mean': feature + '_mean', 'std': feature + '_std'})
    feature_stats.fillna(0, inplace = True)
    df_new_features = pd.concat([df_new_features, feature_stats], axis=1)
# Elimino le colonne composte interamente da zeri
df_new_features = df_new_features.loc[:, (df_new_features != 0).any(axis=0)]
# Converto il DataFrame in una stringa formattata
df_string = df_new_features.to_string(index=False)
# Specifico il percorso del file di output
output_file_path = 'out.txt'  # Sostituisci con il percorso desiderato
# Scrivo la stringa su file
with open(output_file_path, 'w') as file:
    file.write(df_string)
print(f"Il DataFrame è stato scritto su {output_file_path}")

# Spiegazione= raggruppando per label, per ogni feature numerica calcolo le stataistiche principali, metto tutto in un nuovo df e 
# poi elimino le colonne che sono composte interamente da zeri. In questo modo ho un df con le statistiche principali per ogni feature
# e stampo il df su un file di testo, questo per visualizzare meglio i risultati, che da console sarebbe stato molto confusionario.




# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# PUNTO 3: Perform correlation analaysis and visualization through PCA. If you think it could 
# improve the tasks solution, you can do dimensionality reduction for generating the 
# features used in the next tasks.


from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

# Standardizzole nuove caratteristiche
scaler = StandardScaler()
df_new_features_scaled = scaler.fit_transform(df_new_features)

# Eseguo PCA
pca = PCA()
df_pca = pca.fit_transform(df_new_features_scaled)

# Visualizzo la varianza spiegata cumulativa 
explained_variance_ratio_cumulative = pca.explained_variance_ratio_.cumsum()
plt.plot(explained_variance_ratio_cumulative, marker='o')
plt.xlabel('Numero di Componenti Principali')
plt.ylabel('Varianza Spiegata Cumulativa')
plt.title('Varianza Spiegata Cumulativa attraverso PCA')
plt.show()

# Scelgo il numero di componenti principali da mantenere in base alla varianza spiegata
num_components_to_keep = 9  # Ho scelto 9 perche dal grafico era ad occhio il punto di gomito 
# (dove la varianza spiegata cumulativa inizia a crescere molto lentamente)

# Seleziono solo le prime num_components_to_keep colonne del DataFrame PCA
df_pca_selected = pd.DataFrame(df_pca[:, :num_components_to_keep], columns=[f'PC{i+1}' for i in range(num_components_to_keep)])

# Calcolo la matrice delle correlazioni delle nuove componenti principali
pca_correlation_matrix = df_pca_selected.corr()

# Visualizzo la matrice di correlazione attraverso un heatmap
plt.figure(figsize=(12, 8))
sns.heatmap(pca_correlation_matrix, annot=True, cmap='coolwarm', fmt=".2f")
plt.title('Matrice di Correlazione delle Componenti Principali')
plt.show()
# La matrice giustamente viene visualizzata con valori nulli
# tranne in diagonale, perchè le componenti principali sono indipendenti tra loro,


# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# PUNTO 4: Evaluate if you need to scale or standardize data
# Risposta si, è necessario standardizzare i dati, perchè le feature hanno scale 
# diverse e quindi è necessario standardizzarle per poterle confrontare tra loro.
# Standardizzazzione effettuata nel punto 3.




# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------------------------------
# PUNTO 5: Characterize the new final features, by producing plots regarding distributions of
# features (EPDF or ECDF), and correlation analysis.

# Analisi delle correlazioni tra le nuove feature finali
correlation_matrix = df_new_features.corr()

# Visualizzazione 1: Matrice di correlazione (dopo la PCA) attraverso un heatmap
plt.figure(figsize=(40, 20))
sns.heatmap(correlation_matrix, annot=False, cmap='coolwarm', fmt=".2f")
plt.title('Matrice di Correlazione delle Nuove Feature Finali')
plt.show()

# da fare: visualizzazione 2: ECDF delle nuove feature finali o EPDF




