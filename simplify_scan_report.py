'''
Author: Zhongdao Chen
Broad Institute
Last update: May 18th
'''
import re
import xml.etree.ElementTree as ET
import pyfpdf

SEVERITY = 3  # we can define the severity we care about there
vul_counter = 1
kernel_security_count = 0
xml_filename = "xml_69.173.125.60.xml"
app_update = []

pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')  # Extract IP from file name. I know it's ugly. bite me?
asset_ip = str(pattern_ip.findall(xml_filename)).strip("[]'")
separator = "\n----------------------------------------------------------------------------" \
            "----------------------------------------------------------------------------" \
            "--------------------------------------------------\n"

system_kernel_vulnerabilities = ["FreeBSD", "Kernel"]  # these words indicate it's a kernel vulnerabilities,
# we nee to enumerate this list


def get_kernel_security_count():
    global kernel_security_count
    return kernel_security_count


def set_kernel_security_count():
    global kernel_security_count
    kernel_security_count += 1


def get_vul_counter():
    global vul_counter
    return vul_counter


def set_vul_counter():
    global vul_counter
    vul_counter += 1


def get_vulnerability_nodes():
    tests = []
    fp = open("./output.txt", 'w+')
    tree = ET.ElementTree(file=xml_filename)
    root = tree.getroot()
    for child_of_root in root:
        if child_of_root.tag == "VulnerabilityDefinitions":
            vul_defi_root = child_of_root
            for child_of_vul_defi in vul_defi_root:
                if child_of_vul_defi.tag == "vulnerability" and int(child_of_vul_defi.get("severity")) >= SEVERITY:
                    vulnerability_node = child_of_vul_defi

                    if "FreeBSD" in vulnerability_node.get("title") or "Kernel" in vulnerability_node.get("title") \
                            or "Red Hat" in vulnerability_node.get("title"):
                        # NEED TO REWRITE THIS PART TO TRAVERSE WORD LIST, OR JUST KEEP THE CODE UGLY
                        set_kernel_security_count()
                        continue

                    elif "update" in str(vulnerability_node.get("title")):
                        app_update.append(vulnerability_node.get("title"))
                        continue

                    else:
                        print(get_vul_counter(), ":" + str(vulnerability_node.get("title")), " -- Severity: " +
                              str(vulnerability_node.get("severity")), file=fp)
                        set_vul_counter()
                        #  Need to provide more information from the <test> tag
                        for test_node in child_node_test.iter():
                            if str(test_node.tag) == "test" and str(test_node.get("id")) == \
                                    str(vulnerability_node.get("id")):
                                print(test_node.get("id"))
                                for test_node_child in test_node.iter():
                                    if str(test_node_child.text) != "None":
                                        tests.append(' '.join(str(test_node_child.text).split()))
                                        print(test_node_child.tag)
                                    #  STILL HAVE PROBLEM, NEVER HIT
                                    if str(test_node_child.get("LinkURL")) != "None":
                                        tests.append(' '.join(str(test_node_child.get("LinkURL")).split()))

                    for current_node in child_of_vul_defi.iter():
                        #  print(current_node.tag)
                        if current_node.tag == "tags" or current_node.tag == "tag":  # Those tags are not necessary
                            #  print("hit tags")
                            continue

                        elif current_node.tag == "references" or current_node.tag == "reference":
                            #  print("hit references")
                            continue

                        elif current_node.tag == "vulnerability":
                            continue

                        elif current_node.tag == "UnorderedList":
                            continue

                        elif str(current_node.tag) == "URLLink":
                            #  print("hit URLLink")
                            if str(current_node.text) != "":
                                temp = str(current_node.get("LinkURL"))

                            else:
                                temp = str(current_node.get("LinkURL"))

                        else:
                            temp = str(current_node.tag) + str(current_node.attrib) + str(current_node.text)

                        temp = ' '.join(temp.split())
                        temp = temp.replace("Paragraph{}", "").replace("ContainerBlockElement{}", "")
                        temp = temp.replace("description{}", "Description: ")
                        temp = temp.replace("solution{}", "Solution:")
                        temp = temp.replace("references{}", "References:")
                        temp = temp.replace("UnorderedList{}", "")
                        temp = temp.replace("ListItem{}", "")
                        temp = temp.replace("Paragraph", "")
                        temp = temp.replace("{'preformat': 'true'}", "")

                        if temp == "":
                            continue
                        else:
                            print(temp, file=fp)
                    #  output for <test> if valid
                    print("Details:", file=fp)
                    for i in tests:
                        if len(i) != 0:
                            print(i, file=fp)
                    tests = []
                else:
                    # if the severity is not >= what you set, skip
                    continue
            if len(app_update) != 0:
                print("\nAlso, the following applications or protocols are outdated. "
                      "Most of them should be updated automatically after reboot. ", file=fp)
                for app in app_update:
                    print(app, file=fp)
            fp.close()
        elif child_of_root.tag == "nodes":
            child_node_test = child_of_root


def format_output():
    num = 0
    length_of_line = 0
    index = 0
    fp_result = open("./final_report.txt", 'w+')
    print("Scan report for " + str(asset_ip) + "\n", file=fp_result)
    if get_kernel_security_count() >= 1:
        print("***********IMPORTANT***********\n"
              "There are", get_kernel_security_count(), "system kernel vulnerabilities! "
                                                        "Please Reboot to get system patched ASAP."+separator,
              file=fp_result)
    with open('./output.txt') as fp1:
        for line in fp1:
            if len(line) > 100 and " " not in line:
                # This part temporary, I'm gonna write a loop instead after fixing other bugs
                # Or not :)
                if 110 <= len(line) < 220:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    line = ''.join(lst)
                elif 220 <= len(line) < 330:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    line = ''.join(lst)
                elif 330 <= len(line) <= 440:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    line = ''.join(lst)
                elif 440 <= len(line) <= 550:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    lst.insert(440, '-\n')
                    line = ''.join(lst)
                elif len(line) > 550:
                    lst = list(line)
                    lst.insert(110, '-\n')
                    lst.insert(220, '-\n')
                    lst.insert(330, '-\n')
                    lst.insert(440, '-\n')
                    lst.insert(550, '-\n')
                    line = ''.join(lst)
            else:
                lst = line.split(" ")
                #  print(lst)
                for word in lst:
                    #  print(word)
                    if "\n" in word:
                        index = 0
                        length_of_line = 0
                        #  print("length_now = ", length_of_line)
                        continue
                    else:
                        if length_of_line <= 120:
                            length_of_line += len(str(word))
                            #  print("length_now = ", length_of_line)
                            index += 1
                        else:
                            lst.insert(index, '\n')
                            #  print("INDEX:", index)
                            length_of_line = 0
                            #  print("length_now = ", length_of_line)
                line = ' '.join(lst)
            num += 1
            if "Severity" in line and num != 1:
                line = separator + line
            fp_result.write(line)
    fp1.close()
    fp_result.close()


def export_to_pdf():
    pdf = pyfpdf.fpdf.FPDF(format="Letter")
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    with open('./final_report.txt') as fp1:
        for line in fp1:
            if "Scan report for" in line:
                pdf.set_font('Times', size=18)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1, align="C")
            elif "Description" in line or "Solution" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(0, 0, 255)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "Severity" in line or "IMPORTANT" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "applications or protocols" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(255, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)

            elif "Details" in line:
                pdf.set_font('Times', size=10)
                pdf.set_text_color(0, 0, 255)
                pdf.cell(0, 8, line, border=0, ln=1)

            else:
                pdf.set_font("Arial", size=8)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 8, line, border=0, ln=1)
    pdf.output("Simplified_Report.pdf")


get_vulnerability_nodes()
format_output()
export_to_pdf()
