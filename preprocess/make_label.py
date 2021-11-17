# -*- coding:utf-8 -*-
import pickle
import re
import os
import csv
from joern.all import JoernSteps
from igraph import *
from access_db_operate import *
from slice_op import *
from py2neo.packages.httpstream import http
http.socket_timeout = 9999


def make_label(data_path, label_path, _dict):
    f = open("sensifunc_slice_points.pkl", 'rb')
    dict_unsliced_sensifunc = pickle.load(f)
    #print _dict
    #print dict_unsliced_sensifunc
    f.close()
    vulcode_id = {}

    for keys in _dict.keys():  # file:vul_line
        #print keys.split('/')[-1].split('.')[0]
        for key in dict_unsliced_sensifunc.keys():
            for _t in dict_unsliced_sensifunc[key]:
                CVE_ID= _t[0]
                list_sensitive_funcid = _t[1]
                pdg_funcid = _t[2]
                sensitive_funcname = _t[3]
                if keys.split('/')[-1].split('.')[0] != CVE_ID:
                   continue
                else:
                   pdg = getFuncPDGById(key, pdg_funcid)
                   for line in _dict[keys]:
                       #print line
                       for vulline in pdg.vs.select(functionId = pdg_funcid)['location']:
                           #print pdg.vs.select(functionId = pdg_funcid)['location']
                           if int(vulline.split(':')[0]) != line:
                              continue
                           else:
                              if CVE_ID not in vulcode_id.keys():
                                 vulcode_id[CVE_ID] = [pdg.vs.find(location = vulline)['name']]
                              else:
                                 vulcode_id[CVE_ID].append(pdg.vs.find(location = vulline)['name'])

    for key in vulcode_id.keys():
        vulcode_id[key] = list(set(vulcode_id[key]))

    print vulcode_id

    with open('Edges.csv', 'rt') as csvfile:
        reader = csv.DictReader(csvfile)
        column_CVE = [row['CVE_ID'] for row in reader]
    #print column_CVE

    with open('Edges.csv', 'rt') as csvfile:
        reader = csv.DictReader(csvfile)
        column_Label = [row['Label'] for row in reader]
        for i in range(len(column_CVE)):
            _list_label = []
            node = column_Label[i][2:-2].split('\', \'')
            print node
            for target_CVE in vulcode_id.keys():
                if column_CVE[i] != target_CVE:
                   continue
                else:
                   for all_node in node:
                       #print vulcode_id[target_CVE]
                       if all_node in vulcode_id[target_CVE]:
                          _list_label.append(1)
                       else:
                          _list_label.append(0)
                       #print all_node, e123

            #print vulcode_id[target_CVE], e123
            print _list_label
            _dict_label = dict(zip(node, _list_label))
            #print _dict_label
            csv_writer.writerow([column_CVE[i], _dict_label])



    for filename in os.listdir(data_path):
        filepath = os.path.join(data_path, filename)
        #print filepath, filename
        _labels = {}
        f = open(filepath, 'r')
        slicelists = f.read().split('------------------------------')
        #print slicelists
        f.close()

        labelpath = os.path.join(label_path, filename[:-4] + '_label.pkl')
        #print labelpath

        if slicelists[0] == '':
            del slicelists[0]
        if slicelists[-1] == '' or slicelists[-1] == '\n' or slicelists[-1] == '\r\n':
            del slicelists[-1]

        for slice in slicelists:
            sentences = slice.split('\n')
            if sentences[0] == '\r' or sentences[0] == '':
                del sentences[0]
            if sentences == []:
                continue
            if sentences[-1] == '':
                del sentences[-1]
            if sentences[-1] == '\r':
                del sentences[-1]

            slicename = sentences[0]
            label = 0
            key = '/' + ('/').join(slicename.split(' ')[1].split('/')[-4:])  # key in label_source
            if key not in _dict.keys():
                _labels[slicename] = 0
                continue
            if len(_dict[key]) == 0:
                _labels[slicename] = 0
                continue
            sentences = sentences[1:]
            for sentence in sentences:
                if (is_number(sentence.split(' ')[-1])) is False:
                    continue
                linenum = int(sentence.split(' ')[-1])
                vullines = _dict[key]
                if linenum in vullines:
                    label = 1
                    _labels[slicename] = 1
                    break
            if label == 0:
                _labels[slicename] = 0

        with open(labelpath, 'wb') as f1:
            print _labels
            pickle.dump(_labels, f1)
        f1.close()


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False


if __name__ == '__main__':
    with open('./vul_context_func.pkl', 'rb') as f:
        _dict = pickle.load(f)
    #print _dict
    f.close()

    data_path = './slices/'  # source code of software
    label_path = './label_source/'  # labels
    f = open('Node2Label.csv', 'wb')
    csv_writer = csv.writer(f)
    csv_writer.writerow(["CVE_ID", "Node_Label"])

    make_label(data_path, label_path, _dict)
