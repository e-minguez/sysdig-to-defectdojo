#!/usr/bin/env python
import json
import os
import sys
import argparse
import re

def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('--infile', '-i', type=argparse.FileType('r', encoding='UTF-8'), 
                      help="Input file", required=True)
  parser.add_argument('--outfile', '-o', help="Output file", required=True)
  parser.add_argument('--title', '-t', default="Sysdig vulnerability report",
                      help="Report title (default: Sysdig vulnerability report).",
                      required=False)
  args = parser.parse_args()
  return args

def main():
  args=parse_args()
  try:
    with open(args.infile.name) as f:
      sourcejson = json.load(f)
  except ValueError as e:
    print('invalid json: %s' % args.infile.name)
    return None

  outfile = args.outfile
  reportdate = os.path.basename(args.infile.name).split("-")[0]
  reportdate = reportdate[:4] + '-' + reportdate[4:6] + '-' + reportdate[6:]
  destjson = {}
  destjson["title"] = args.title
  destjson["findings"] = []
  
  
  for dic in sourcejson['data']:
    description = f"""packageName: {dic["packageName"]}
                      packageType: {dic["packageType"]}
                      packagePath: {dic["packagePath"]}
                      packageVersion: {dic["packageVersion"]}
                      imagePullString: {dic["imagePullString"]}
                      imageId: {dic["imageId"]}
                      osName: {dic["osName"]}
                      vulnCvssVersion: {dic["vulnCvssVersion"]}
                      vulnCvssScore: {dic["vulnCvssScore"]}
                      vulnCvssVector: {dic["vulnCvssVector"]}
                      """
    mitigation = f"""vulnFixAvailable: {dic["vulnFixAvailable"]}
                      vulnFixVersion: {dic["vulnFixVersion"]}
                      vulnDisclosureDate: {dic["vulnDisclosureDate"]}
                      vulnSolutionDate: {dic["vulnSolutionDate"] if "vulnSolutionDate" in dic else ''}
                      vulnExploitable: {dic["vulnExploitable"]}
                      packageSuggestedFix: {dic["packageSuggestedFix"]}
                  """
    impact = f"""k8sClusterName: {dic["k8sClusterName"]}
                 k8sNamespaceName: {dic["k8sNamespaceName"]}
                 k8sWorkloadType: {dic["k8sWorkloadType"]}
                 k8sWorkloadName: {dic["k8sWorkloadName"]}
                 k8sPodContainerName: {dic["k8sPodContainerName"]}
                 k8sPodCount: {dic["k8sPodCount"]}
              """
    destjson["findings"].append({
      "date": reportdate,
      "title": dic["vulnName"],
      "cve": dic["vulnName"],
      "severity": dic["vulnSeverity"],
      "impact": re.sub('\n +', '\n', impact),
      "mitigation": re.sub('\n +', '\n', mitigation),
      "description": re.sub('\n +', '\n', description),
      "references": dic["vulnLink"]
    })

  with open(outfile, "w") as outfile:
    outfile.write(json.dumps(destjson))

if __name__ == "__main__":
    main()