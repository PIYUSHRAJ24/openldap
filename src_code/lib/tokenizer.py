import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.probability import FreqDist
import string
from textblob import TextBlob


class Tokenizer:
    def __init__(self):
        self.active = True

    def tokenize(self, filename, data):
        
        blob = TextBlob(data)

        # Tokenize the data
        tokens = word_tokenize(data)
        tagged_words = blob.pos_tags

        # Extract only the nouns
        nouns = [word for word, tag in tagged_words if tag in ['NN', 'NNS', 'NNP', 'NNPS']]
        
        tokens += nouns
        
        # Perform additional preprocessing steps, such as removing stop words and stemming
        stop_words = set(stopwords.words('english'))
        excluded_words = [stop_words, string.punctuation, 'the', 'date', 'print', 'inr', 'not', 'yes', 'true', 'false']
        tokens = [token for token in nouns if token.lower() not in excluded_words and len(token) > 2]

        # Perform stemming
        stemmer = nltk.stem.PorterStemmer()
        tokens = [stemmer.stem(token) for token in tokens]

        # Create a frequency distribution of the words
        fdist = FreqDist(tokens)

        print("All tokens: ", list(fdist.items()))

        # Extract the top 50 keywords
        tokens = fdist.most_common(50)
        print('\nSuggested Tokens: ', tokens)
        words = list(map(lambda s:s[0], tokens))
        return words.append(filename)
