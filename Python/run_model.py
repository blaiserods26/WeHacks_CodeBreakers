
import torch
import h5py
from transformers import RobertaTokenizer, RobertaForSequenceClassification

# Define the model architecture
model = RobertaForSequenceClassification.from_pretrained('roberta-base', num_labels=2)

# Load the state dictionary from the HDF5 file
state_dict = {}
with h5py.File('model.h5', 'r') as f:
    for key in f.keys():
        state_dict[key] = torch.tensor(f[key][:])

# Load the state dictionary into the model
model.load_state_dict(state_dict)
model.eval()  # Set the model to evaluation mode

# Load the tokenizer
tokenizer = RobertaTokenizer.from_pretrained('roberta-base')

# Example input text
texts=[""" """]
# Tokenize the input text
encodings = tokenizer(texts, truncation=True, padding=True, max_length=512, return_tensors='pt')

# Make predictions
with torch.no_grad():
    outputs = model(**encodings)
    predictions = outputs.logits.argmax(dim=-1)

# Print the predictions
print(predictions)