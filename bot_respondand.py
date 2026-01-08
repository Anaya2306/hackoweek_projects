def faq_bot(user_input):
    q = user_input.lower()

    if "timing" in q or "hours" in q or "open" in q:
        return "Our institute is open from 9:00 AM to 5:00 PM, Monday to Friday."

    elif "fees" in q or "fee structure" in q:
        return "The annual fee is ₹50,000. Installment options are available."

    elif "courses" in q or "programs" in q:
        return "We offer courses in Computer Science, Business Management, and Data Science."

    elif "admission" in q or "apply" in q:
        return "Admissions are open from June to August. Apply online through our website."

    elif "contact" in q or "phone" in q:
        return "You can contact us at +91-9876543210."

    elif "email" in q:
        return "Our email address is info@institute.com."

    elif "address" in q or "location" in q:
        return "We are located at MG Road, Bangalore, India."

    elif "hostel" in q:
        return "Yes, hostel facilities are available for both boys and girls."

    elif "scholarship" in q:
        return "Scholarships are available for meritorious and economically weaker students."

    elif "placement" in q:
        return "We provide 100% placement assistance with top companies."

    elif "library" in q:
        return "The library is open from 9 AM to 6 PM with digital and physical resources."

    elif "exam" in q:
        return "Exams are conducted at the end of each semester."

    elif "holiday" in q:
        return "The institute follows a government-approved academic calendar."

    elif "principal" in q:
        return "The principal of the institute is Dr. R. Sharma."

    else:
        return "Sorry, I couldn't understand your question. Please contact the office."


while True:
    user = input("You: ")
    if user.lower() == "exit":
        print("Bot: Thank you! Have a great day.")
        break
    print("Bot:", faq_bot(user))