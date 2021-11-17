from general_op import *
import csv


def sub_slice_backwards(backward_edge, startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return backward_edge, list_node, not_scan_list
    else:
        list_node.append(startnode)
        not_scan_list.append(startnode['name'])

    predecessors = startnode.predecessors()
    # print predecessors
    if predecessors != []:
        for p_node in predecessors:
            print[int(p_node['name']), int(startnode['name'])], p_node['code'], startnode['code']
            # csv_writer.writerow([int(p_node['name']), int(startnode['name']), p_node['code'], startnode['code']])
            backward_edge.append([int(p_node['name']), int(startnode['name'])])
            # print backward_edge
            backward_edge, list_node, not_scan_list = sub_slice_backwards(backward_edge, p_node, list_node,
                                                                          not_scan_list)

    return backward_edge, list_node, not_scan_list


def program_slice_backwards(pdg, list_startNode):  # startNode is a list
    list_all_node = []
    not_scan_list = []
    backward_edge = []
    CVE_ID = list_startNode[0]['filepath'].split('/')[-1].split('.')[0]
    # print list_startNode, CVE_ID, e123

    for startNode in list_startNode:
        list_node = [startNode]
        not_scan_list.append(startNode['name'])  # id of startNode
        predecessors = startNode.predecessors()  # output all predecessors->startNode
        print
        "Target node_ID is {}, slicing statement is '{}'".format(startNode['name'], startNode['code'])
        if predecessors != []:
            for p_node in predecessors:
                # print p_node['name']
                print[int(p_node['name']), int(not_scan_list[0])], p_node['code'], startNode['code']
                # csv_writer.writerow([int(p_node['name']), int(not_scan_list[0]), p_node['code'], startNode['code']])
                backward_edge.append([int(p_node['name']), int(not_scan_list[0])])
                # print backward_edge
                backward_edge, list_node, not_scan_list = sub_slice_backwards(backward_edge, p_node, list_node,
                                                                              not_scan_list)

        list_all_node += list_node
        # print e123

        # Add function define line
        if startNode['functionId'] in not_scan_list:
            continue
        for node in pdg.vs:
            if node['name'] == startNode['functionId']:
                list_all_node.append(node)
                not_scan_list.append(node['name'])
                break

    # print("list_all_node:", list_all_node)
    list_ordered_node = sortedNodesByLoc(list_all_node)

    _list_re = []
    a = 0
    while a < len(list_ordered_node):
        if list_ordered_node[a]['name'] not in _list_re:
            _list_re.append(list_ordered_node[a]['name'])
            a += 1
        else:
            del list_ordered_node[a]
    # print backward_edge
    # print list_ordered_node
    return backward_edge, list_ordered_node


def sub_slice_forward(edge, startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return edge, list_node, not_scan_list

    else:
        list_node.append(startnode)
        not_scan_list.append(startnode['name'])

    successors = startnode.successors()
    # print successors
    if successors != []:
        for p_node in successors:
            print[int(startnode['name']), int(p_node['name'])], startnode['code'], p_node['code']
            # csv_writer.writerow([int(startnode['name']), int(p_node['name']), startnode['code'], p_node['code']])
            edge.append([int(not_scan_list[0]), int(p_node['name'])])
            edge, list_node, not_scan_list = sub_slice_forward(edge, p_node, list_node, not_scan_list)

    return edge, list_node, not_scan_list


def program_slice_forward(edge, pdg,
                          list_startNode):  # startNode is a list of parameters, only consider data dependency
    pdg = del_ctrl_edge(pdg)
    # print edge
    list_all_node = []
    not_scan_list = []
    # print list_startNode
    # print e123
    for startNode in list_startNode:
        list_node = [startNode]
        not_scan_list.append(startNode['name'])
        successors = startNode.successors()
        # print startNode['name']
        # print successors

        if successors != []:
            for p_node in successors:
                # csv_writer.writerow([int(not_scan_list[0]), int(p_node['name']), startNode['code'], p_node['code']])
                print[int(not_scan_list[0]), int(p_node['name'])], startNode['code'], p_node['code']
                edge.append([int(not_scan_list[0]), int(p_node['name'])])
                edge, list_node, not_scan_list = sub_slice_forward(edge, p_node, list_node, not_scan_list)

        list_all_node += list_node

    list_ordered_node = sortedNodesByLoc(list_all_node)

    a = 0
    _list_re = []
    while a < len(list_ordered_node):
        if list_ordered_node[a]['name'] not in _list_re:
            _list_re.append(list_ordered_node[a]['name'])
            a += 1
        else:
            del list_ordered_node[a]

    return edge, list_ordered_node


def process_cross_func(to_scan_list, testID, slicetype, list_result_node, not_scan_func_list):
    if to_scan_list == []:
        return list_result_node, not_scan_func_list

    # print not_scan_func_list

    for node in to_scan_list:
        if node['name'] in not_scan_func_list:
            continue

        ret = isNewOrDelOp(node, testID)  # c++ new or delete memory
        if ret:
            funcname = ret
            pdg = getFuncPDGByNameAndtestID(funcname, testID)

            if pdg == False:
                not_scan_func_list.append(node['name'])
                continue

            else:
                result_list = sortedNodesByLoc(pdg.vs)

                not_scan_func_list.append(node['name'])

                index = 0
                for result_node in list_result_node:
                    if result_node['name'] == node['name']:
                        break
                    else:
                        index += 1

                list_result_node = list_result_node[:index + 1] + result_list + list_result_node[index + 1:]

                list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype,
                                                                          list_result_node, not_scan_func_list)


        else:
            ret = isFuncCall(node)  # if funccall ,if so ,return funcnamelist
            if ret:
                for funcname in ret:
                    # print funcname
                    if funcname.find('->') != -1:
                        real_funcname = funcname.split('->')[-1].strip()
                        objectname = funcname.split('->')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue

                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID_noctrl(funcname, testID)


                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByNameAndtestID_noctrl(funcID, testID)
                        if src_pdg == False:
                            continue
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    else:
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)
                        # print testID, pdg

                    if pdg == False:
                        not_scan_func_list.append(node['name'])
                        continue

                    else:
                        print
                        slicetype
                        if slicetype == 0:
                            ret_node = []
                            for vertex in pdg.vs:
                                print
                                vertex
                                if vertex['type'] == 'ReturnStatement':
                                    ret_node.append(vertex)

                            result_list = program_slice_backwards(pdg, ret_node)
                            not_scan_func_list.append(node['name'])

                            index = 0
                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            list_result_node = list_result_node[:index + 1] + result_list + list_result_node[index + 1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype,
                                                                                      list_result_node,
                                                                                      not_scan_func_list)

                        elif slicetype == 1:
                            param_node = []
                            FuncEntryNode = False
                            for vertex in pdg.vs:
                                if vertex['type'] == 'Parameter':
                                    param_node.append(vertex)
                                elif vertex['type'] == 'Function':
                                    FuncEntryNode = vertex

                            print[int(node['name']), int(param_node[0]['name'])], node['code'], param_node[0]['code']
                            if param_node != []:
                                result_list = program_slice_forward(pdg, param_node)
                            else:
                                result_list = sortedNodesByLoc(pdg.vs)

                            not_scan_func_list.append(node['name'])
                            index = 0

                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            if FuncEntryNode != False:
                                result_list.insert(0, FuncEntryNode)

                            list_result_node = list_result_node[:index + 1] + result_list + list_result_node[index + 1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype,
                                                                                      list_result_node,
                                                                                      not_scan_func_list)

    return list_result_node, not_scan_func_list


def process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list):
    # is not a good way in time, list_tuple_results_back=[(results_back, itertimes)]
    while i < len(list_tuple_results_back):
        iter_time = list_tuple_results_back[i][1]
        if iter_time == 3 or iter_time == -1:  # allow cross 3 funcs:
            i += 1
            continue

        else:
            list_node = list_tuple_results_back[i][0]

            if len(list_node) == 1:
                i += 1
                continue

            if list_node[1]['type'] == 'Parameter':
                func_name = list_node[0]['name']
                path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')

                if not os.path.exists(path):
                    i += 1
                    continue

                fin = open(path, 'rb')
                _dict = pickle.load(fin)
                fin.close()

                if func_name not in _dict.keys():
                    list_tuple_results_back[i][1] = -1
                    i += 1
                    continue

                else:
                    list_cfgNodeID = _dict[func_name]
                    dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)
                    iter_time += 1
                    _new_list = []
                    for item in dict_func_pdg.items():
                        targetPDG = item[1]
                        startnode = []
                        for n in targetPDG.vs:
                            if n['name'] == item[0]:  # is id
                                startnode = [n]
                                break

                        if startnode == []:
                            continue
                        ret_list = program_slice_backwards(targetPDG, startnode)
                        not_scan_func_list.append(startnode[0]['name'])

                        ret_list = ret_list + list_node
                        _new_list.append([ret_list, iter_time])

                    if _new_list != []:
                        del list_tuple_results_back[i]
                        list_tuple_results_back = list_tuple_results_back + _new_list
                        list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(
                            list_tuple_results_back, testID, i, not_scan_func_list)
                    else:
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue


            else:
                funcname = list_node[0]['code']
                if funcname.find("::") > -1:

                    path = os.path.join('dict_call2cfgNodeID_funcID', testID,
                                        'dict.pkl')  # get funname and it call place
                    if not os.path.exists(path):
                        i += 1
                        continue

                    # Modified by kingnop
                    if not os.path.exists(path):
                        i += 1
                        continue
                    ####################

                    fin = open(path, 'rb')
                    _dict = pickle.load(fin)
                    fin.close()

                    func_name = list_node[0]['name']
                    if func_name not in _dict.keys():
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue

                    else:
                        list_cfgNodeID = _dict[func_name]
                        dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)

                        iter_time += 1
                        _new_list = []
                        for item in dict_func_pdg.items():
                            targetPDG = item[1]
                            startnode = []
                            for n in targetPDG.vs:
                                if n['name'] == item[0]:  # is id
                                    startnode = [n]
                                    break
                            if startnode == []:
                                continue
                            ret_list = program_slice_backwards(targetPDG, startnode)
                            not_scan_func_list.append(startnode[0]['name'])

                            ret_list = ret_list + list_node
                            _new_list.append([ret_list, iter_time])

                        if _new_list != []:
                            del list_tuple_results_back[i]
                            list_tuple_results_back = list_tuple_results_back + _new_list
                            list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(
                                list_tuple_results_back, testID, i, not_scan_func_list)

                        else:
                            list_tuple_results_back[i][1] = -1
                            i += 1
                            continue

                else:
                    i += 1
                    continue

    return list_tuple_results_back, not_scan_func_list

