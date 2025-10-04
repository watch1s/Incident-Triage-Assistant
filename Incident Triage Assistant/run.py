import argparse
#from ast import Str
import os.path
from src.triage_engine import triage_log_file
import json
import sys
import os


def main():
    parser = argparse.ArgumentParser(prog="Incident Triage Assistant",
        description="Automatically triage security logs using IOCs and risk scoring.",
        epilog="Example: python run.py -l data/sample_logs.json -i rules/iocs.txt -o reports/my_report.json")
    
    
    #Adds arguments for essential app functions
    parser.add_argument('--logs','-l',required=True,type=str)
    parser.add_argument('--iocs','-i',required=True,type=str)
    parser.add_argument('--output','-o',required=False,type=str,default='reports/triage_report.json',help='Help to change save direction of the triage report')

    args = parser.parse_args()

    #Checks locations
    if not os.path.exists(args.logs):
       print(f"Logs doesn't exist!, Path: {args.logs}")
       exit(1)
    if not os.path.exists(args.iocs):
        print(f"Iocs doesn't exist!, Path: {args.iocs}")
        exit(1)

    
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    #Saving the triage results file
    results = triage_log_file(args.logs,args.iocs)
    #print(triage_log_file.__annotations__)

    with open(args.output, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"Triage completed! Report saved to {args.output}")

    pass




if __name__ == "__main__":
    main()
 
