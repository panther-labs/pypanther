import json


def calculate_uniqueness_score(alerts):
    titles = [alert["title"] for alert in alerts]
    unique_titles = set(titles)
    total_alerts = len(titles)
    unique_alerts = len(unique_titles)

    uniqueness_ratio = unique_alerts / total_alerts

    if uniqueness_ratio > 0.9:
        return "A"
    if uniqueness_ratio > 0.75:
        return "B"
    if uniqueness_ratio > 0.5:
        return "C"
    if uniqueness_ratio > 0.25:
        return "D"
    return "F"


def analyze_alerts(data):
    for rule in data:
        alerts = rule["alerts"]
        score = calculate_uniqueness_score(alerts)
        rule["uniqueness_score"] = score
    return data


def main():
    with open("out.json") as file:
        data = json.load(file)

    analyzed_data = analyze_alerts(data)

    with open("analyzed_out.json", "w") as file:
        json.dump(analyzed_data, file, indent=4)


if __name__ == "__main__":
    main()
