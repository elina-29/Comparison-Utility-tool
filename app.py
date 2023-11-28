from flask import Flask, render_template, request, redirect, url_for
import os
from PyPDF2 import PdfReader
import pandas as pd
from bs4 import BeautifulSoup
import io
import csv
from io import TextIOWrapper

app = Flask(__name__)
def extract_text_from_pdf(pdf_file):
    text = ""
    pdf_reader = PdfReader(io.BytesIO(pdf_file.read()))
    for page in pdf_reader.pages:
        text += page.extract_text()
    return text

def extract_text_from_html(html_file):
    html_content = html_file.read()
    soup = BeautifulSoup(html_content, 'html.parser')

    error_table = soup.find('table', class_='table table-striped text-center')

    severities = []
    error_messages = []

    rows = error_table.find('tbody').find_all('tr')

    for row in rows:
        severity_td = row.find('td', class_=True)
        if severity_td:
            severity = severity_td['class'][0].replace('bg-severity-', '')
            severities.append(severity)

        error_message_td = row.find_all('td')[1]
        if error_message_td:
            error_message = error_message_td.get_text(strip=True)
            error_messages.append(error_message)

    result = '\n'.join([f"{severities[i]}: {error_messages[i]}" for i in range(len(severities))])

    return result

def compare_text(previous_text, current_text):
    previous_errors = set(previous_text.split('\n'))
    current_errors = set(current_text.split('\n'))

    new_errors = current_errors - previous_errors
    resolved_errors = previous_errors - current_errors

    return new_errors, resolved_errors

def filter_errors_by_severity(errors, severities):
    filtered_errors = [error for error in errors if any(error.lower().startswith(severity) for severity in severities)]
    return filtered_errors

def compare_csv_files(file1, file2):
    # Read the contents of both uploaded CSV files into dictionaries indexed by the Plugin ID
    data1 = {}
    data2 = {}

    # Read and process the first file (file1)
    if isinstance(file1.stream, io.TextIOBase):
        file1_stream = file1.stream
    else:
        file1_stream = io.TextIOWrapper(file1.stream, encoding='utf-8')

    csv_reader1 = csv.DictReader(file1_stream)

    for row in csv_reader1:
        plugin_id = row['Plugin ID']
        data1[plugin_id] = row

    # Read and process the second file (file2)
    if isinstance(file2.stream, io.TextIOBase):
        file2_stream = file2.stream
    else:
        file2_stream = io.TextIOWrapper(file2.stream, encoding='utf-8')

    csv_reader2 = csv.DictReader(file2_stream)

    for row in csv_reader2:
        plugin_id = row['Plugin ID']
        data2[plugin_id] = row

    # Compare the two CSV files to find new and resolved errors
    new_errors = [row for plugin_id, row in data2.items() if plugin_id not in data1]
    resolved_errors = [row for plugin_id, row in data1.items() if plugin_id not in data2]

    return new_errors, resolved_errors


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        selected_extension = request.form.get("file_extension")

        if selected_extension == "pdf":
            return redirect(url_for("app1"))
        elif selected_extension=="html":
            return redirect(url_for("app1"))
        elif selected_extension == "xls":
            return redirect(url_for("app2"))
        elif selected_extension=="csv":
            return redirect(url_for("app3"))

    return render_template("index.html")

@app.route("/app1", methods=['GET', 'POST'])
def app1():
    new_errors = []
    resolved_errors = []
    info_lines = []

    if request.method == "POST":
        previous_file = request.files["previous_file"]
        current_file = request.files["current_file"]

        if previous_file and current_file:
            previous_filename = previous_file.filename
            current_filename = current_file.filename

            if previous_filename.endswith(".pdf") and current_filename.endswith(".pdf"):
                previous_text = extract_text_from_pdf(previous_file)
                current_text = extract_text_from_pdf(current_file)
            elif previous_filename.endswith(".html") and current_filename.endswith(".html"):
                previous_text = extract_text_from_html(previous_file)
                current_text = extract_text_from_html(current_file)
            else:
                return "Unsupported file formats. Please upload PDF or HTML files."

            new_errors, resolved_errors = compare_text(previous_text, current_text)
            info_lines = [line.strip() for line in current_text.split("\n") if line.lower().startswith("info")]

    severities_to_print = ["low", "medium", "critical", "high"]
    new_errors = filter_errors_by_severity(new_errors, severities_to_print)
    resolved_errors = filter_errors_by_severity(resolved_errors, severities_to_print)

    new_errors_count = len(new_errors)
    resolved_errors_count = len(resolved_errors)

    return render_template(
        "app1_index.html",
        new_errors=new_errors,
        resolved_errors=resolved_errors,
        info_lines=info_lines,
        new_errors_count=new_errors_count,
        resolved_errors_count=resolved_errors_count
    )


@app.route("/app2", methods=["GET", "POST"])
def app2():

    new_errors_message = ""  # Initialize with a default value
    resolved_errors_message = ""  # Initialize with a default value

    if request.method == "POST":

        previous_file = request.files["previous_file"]
        current_file = request.files["current_file"]

        previous_df = pd.read_excel(previous_file)
        current_df = pd.read_excel(current_file)

        expected_columns = ["Vulnerability Id", "Severity"]

        if not set(expected_columns).issubset(previous_df.columns) or not set(expected_columns).issubset(current_df.columns):
            return "Error: Column names in Excel files are not as expected."

        merged_df = pd.merge(previous_df, current_df, on="Vulnerability Id", how="outer", suffixes=("_previous", "_current"))

        new_errors = merged_df[merged_df["Severity_previous"].isna() & ~merged_df["Severity_current"].isna()]

        resolved_errors = merged_df[~merged_df["Severity_previous"].isna() & merged_df["Severity_current"].isna()]

        new_errors = new_errors.dropna(axis=1, how="all")
        resolved_errors = resolved_errors.dropna(axis=1, how="all")

        total_new_errors = len(new_errors)

        if total_new_errors>0:
            new_critical_errors = new_errors[new_errors["Severity_current"] == "Critical"].shape[0]
            new_high_errors = new_errors[new_errors["Severity_current"] == "High"].shape[0]
            new_medium_errors = new_errors[new_errors["Severity_current"] == "Medium"].shape[0]
            new_low_errors = new_errors[new_errors["Severity_current"] == "Low"].shape[0]
        else:
            new_critical_errors=0
            new_high_errors=0
            new_medium_errors=0
            new_low_errors=0
            new_errors_message = "No new errors found."


        # Calculate total number of resolved errors
        total_resolved_errors = len(resolved_errors)

        if total_resolved_errors>0:
            resolved_critical_errors = resolved_errors[resolved_errors["Severity_previous"] == "Critical"].shape[0]
            resolved_high_errors = resolved_errors[resolved_errors["Severity_previous"] == "High"].shape[0]
            resolved_medium_errors = resolved_errors[resolved_errors["Severity_previous"] == "Medium"].shape[0]
            resolved_low_errors = resolved_errors[resolved_errors["Severity_previous"] == "Low"].shape[0]
        else:
            resolved_critical_errors=0
            resolved_high_errors=0
            resolved_medium_errors=0
            resolved_low_errors=0
            resolved_errors_message = "No resolved errors found."

        return render_template(
            "app2_result.html",
            new_errors=new_errors,
            new_errors_message=new_errors_message,
            resolved_errors=resolved_errors,
            resolved_errors_message=resolved_errors_message,
            total_new_errors=total_new_errors,
            new_critical_errors=new_critical_errors,
            new_high_errors=new_high_errors,
            new_medium_errors=new_medium_errors,
            new_low_errors=new_low_errors,
            total_resolved_errors=total_resolved_errors,
            resolved_critical_errors=resolved_critical_errors,
            resolved_high_errors=resolved_high_errors,
            resolved_medium_errors=resolved_medium_errors,
            resolved_low_errors=resolved_low_errors,
        )


        # Check if there are no new or resolved errors
        # if new_errors.empty and resolved_errors.empty:
        #     new_errors_message = "No new errors found."
        #     resolved_errors_message = "No resolved errors found."
        # else:
        #     new_errors_message = ""
        #     resolved_errors_message = ""
        #     return render_template(
        #         "app2_result.html",
        #         new_errors=new_errors,
        #         new_errors_message=new_errors_message,
        #         resolved_errors=resolved_errors,
        #         resolved_errors_message=resolved_errors_message,
        #         total_new_errors=total_new_errors,
        #         new_critical_errors=new_critical_errors,
        #         new_high_errors=new_high_errors,
        #         new_medium_errors=new_medium_errors,
        #         new_low_errors=new_low_errors,
        #         total_resolved_errors=total_resolved_errors,
        #         resolved_critical_errors=resolved_critical_errors,
        #         resolved_high_errors=resolved_high_errors,
        #         resolved_medium_errors=resolved_medium_errors,
        #         resolved_low_errors=resolved_low_errors,
        # )
    return render_template("app2_index.html")

@app.route("/app3", methods=["GET", "POST"])
def app3():
    if request.method == "POST":
        file1 = request.files['file1']
        file2 = request.files['file2']

        if file1 and file2:
            new_errors, resolved_errors = compare_csv_files(file1, file2)
            new_errors_count = len(new_errors)
            resolved_errors_count = len(resolved_errors)
        
        return render_template('app3_results.html', new_errors=new_errors, resolved_errors=resolved_errors,new_errors_count=new_errors_count,
        resolved_errors_count=resolved_errors_count)
    return render_template('app3_upload.html')


if __name__ == "__main__":
    app.run(debug=True)
