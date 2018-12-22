
import pandas as pd
import numpy as np
import hashlib
import json
import sys, getopt
import string
from secrets import token_hex

if sys.version_info < (3, 6):
   import sha3

def anonymize(inFile, outFile, cols, dict_file):
   df=pd.read_csv(inFile)
   pat_dict={}
   inv_pat_dict={}
   for pid in df.PatID.unique():
       hashedpid=hashlib.sha3_512(pid.encode()).hexdigest()
       pat_dict[hashedpid]=pid
       inv_pat_dict[pid]=hashedpid

   doc_dict={}
   inv_doc_dict={}
   for did in df.DocID.unique():
       hasheddid=hashlib.sha3_512(did.encode()).hexdigest()
       doc_dict[hasheddid]=did
       inv_doc_dict[did]=hasheddid

   df.PatID=df.PatID.apply(lambda x: hashlib.sha3_512(x.encode()).hexdigest())
   df.DocID=df.DocID.apply(lambda x: hashlib.sha3_512(x.encode()).hexdigest())

   df.to_csv(outFile, index=False)

   all_dicts={}
   all_dicts['patients']=pat_dict
   all_dicts['inv_patients']=inv_pat_dict
   all_dicts['doctors']=doc_dict
   all_dicts['inv_doctors']=inv_doc_dict

   with open(dict_file, 'w') as f:
       json.dump(all_dicts, f)


def anonymize_with_secret(inFile, outFile, cols, dict_file, secret):
   df=pd.read_csv(inFile)
   pat_dict={}
   inv_pat_dict={}
   for pid in df.PatID.unique():
       spid=secret+str(pid)
       hashedpid=hashlib.sha3_512(spid.encode()).hexdigest()
       pat_dict[hashedpid]=pid
       inv_pat_dict[pid]=hashedpid

   doc_dict={}
   inv_doc_dict={}
   for did in df.DocID.unique():
       sdid=secret+str(did)
       hasheddid=hashlib.sha3_512(sdid.encode()).hexdigest()
       doc_dict[hasheddid]=did
       inv_doc_dict[did]=hasheddid

   df.PatID=df.PatID.apply(lambda x: hashlib.sha3_512((secret+str(x)).encode()).hexdigest())
   df.DocID=df.DocID.apply(lambda x: hashlib.sha3_512((secret+str(x)).encode()).hexdigest())

   df.to_csv(outFile, index=False)

   all_dicts={}
   all_dicts['secret']=secret
   all_dicts['patients']=pat_dict
   all_dicts['inv_patients']=inv_pat_dict
   all_dicts['doctors']=doc_dict
   all_dicts['inv_doctors']=inv_doc_dict

   with open(dict_file, 'w') as f:
       json.dump(all_dicts, f)





def main(argv):
   inputfile = ''
   outputfile = ''
   cols=''
   try:
      opts, args = getopt.getopt(argv,"hi:o:d:c:",["ifile=","ofile=","dfile=","cols="])
   except getopt.GetoptError:
      print('Use: python anonymizer.py -i <inputfile> -o <outputfile> -d <dictionary file> -c <comma separated column list>')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
        print('Use: python anonymizer.py -i <inputfile> -o <outputfile> -d <dictionary file> -c <comma separated column list>')
        sys.exit()
      elif opt in ("-i", "--ifile"):
         inputfile = arg
      elif opt in ("-o", "--ofile"):
         outputfile = arg
      elif opt in ("-d", "--dfile"):
         dictfile = arg
      elif opt in ("-c", "--cols"):
         columns = arg.split(',')
   secret=token_hex(64)
   anonymize_with_secret(inputfile, outputfile, columns, dictfile, secret)



if __name__ == "__main__":
   main(sys.argv[1:])
