def calculate_paystack_fee(amount):
    # Paystack charges 1.5% + NGN 100 for local transactions
    base_fee = 0.015 * amount  # 1.5% fee

    # Add the additional NGN 100 charge for transactions above NGN 2500
    additional_fee = 10000 if amount > 250000 else 0  # Convert to kobo

    total_fee = base_fee + additional_fee

    # Cap the fee at NGN 2000 (200,000 kobo) for transactions above NGN 133,333.33
    return min(total_fee, 200000)  # 2000 NGN is the max fee (in kobo)
    
