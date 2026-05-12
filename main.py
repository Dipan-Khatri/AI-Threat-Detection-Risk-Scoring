
import re
from collections import defaultdict

EVENT_RISK_POINTS = {
    "EMAIL_RECEIVED": 5,
    "LINK_CLICKED": 25,
    "LOGIN_FAILED": 10,
    "LOGIN_SUCCESS": 20,
    "PASSWORD_CHANGED": 30,
    "MAILBOX_FORWARDING_ENABLED": 50
}

SUSPICIOUS_LOCATIONS = {"Russia", "China", "Unknown"}


def extract_field(line, field_name):
    pattern = rf'{field_name}=("[^"]+"|\S+)'
    match = re.search(pattern, line)

    if match:
        return match.group(1).replace('"', "")

    return None


def get_risk_level(score):
    if score >= 80:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def get_recommendation(risk_level):
    if risk_level == "HIGH":
        return "Disable account, reset password, remove forwarding rules, and investigate immediately."
    elif risk_level == "MEDIUM":
        return "Review user activity, monitor login behavior, and verify user identity."
    return "Continue monitoring."


def analyze_events(file_path):
    user_scores = defaultdict(int)
    user_events = defaultdict(list)

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            user = extract_field(line, "USER")
            event = extract_field(line, "EVENT")
            location = extract_field(line, "LOCATION")
            ip = extract_field(line, "IP")

            if not user or not event:
                continue

            risk_points = EVENT_RISK_POINTS.get(event, 0)

            if location in SUSPICIOUS_LOCATIONS:
                risk_points += 25

            user_scores[user] += risk_points
            user_events[user].append({
                "event": event,
                "ip": ip if ip else "N/A",
                "location": location if location else "N/A",
                "risk_points": risk_points
            })

    return user_scores, user_events


def print_report(user_scores, user_events):
    print("\n=== AI Threat Detection Risk Report ===\n")

    for user, score in sorted(user_scores.items(), key=lambda x: x[1], reverse=True):
        risk_level = get_risk_level(score)
        recommendation = get_recommendation(risk_level)

        print(f"User: {user}")
        print(f"Risk Score: {score}")
        print(f"Risk Level: {risk_level}")
        print("Events:")

        for event in user_events[user]:
            print(
                f"  - {event['event']} | IP: {event['ip']} | "
                f"Location: {event['location']} | Points: {event['risk_points']}"
            )

        print(f"Recommendation: {recommendation}")
        print("-" * 70)


def save_report(user_scores, user_events, output_file="risk_report.txt"):
    with open(output_file, "w") as report:
        report.write("AI Threat Detection Risk Report\n")
        report.write("=" * 70 + "\n\n")

        for user, score in sorted(user_scores.items(), key=lambda x: x[1], reverse=True):
            risk_level = get_risk_level(score)
            recommendation = get_recommendation(risk_level)

            report.write(f"User: {user}\n")
            report.write(f"Risk Score: {score}\n")
            report.write(f"Risk Level: {risk_level}\n")
            report.write("Events:\n")

            for event in user_events[user]:
                report.write(
                    f"  - {event['event']} | IP: {event['ip']} | "
                    f"Location: {event['location']} | Points: {event['risk_points']}\n"
                )

            report.write(f"Recommendation: {recommendation}\n")
            report.write("-" * 70 + "\n")


if __name__ == "__main__":
    scores, events = analyze_events("security_events.txt")
    print_report(scores, events)
    save_report(scores, events)

    print("\nReport saved to risk_report.txt")
