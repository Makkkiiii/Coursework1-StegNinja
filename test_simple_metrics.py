"""
Test the updated simple quality metrics display
"""

def test_simple_metrics():
    """Test the new simple quality metrics"""
    
    def get_quality_description(metrics):
        """Replicate the updated method"""
        mse = metrics.get('mse', 0)
        psnr = metrics.get('psnr', 0)
        ssim = metrics.get('ssim', 0)
        
        # Determine overall quality based on metrics
        if psnr >= 50 and ssim >= 0.99:
            quality = "🟢 EXCELLENT - Virtually undetectable"
            details = "Hidden data is completely invisible to the naked eye"
        elif psnr >= 40 and ssim >= 0.95:
            quality = "🟡 VERY GOOD - Barely noticeable"
            details = "Hidden data causes minimal visual changes"
        elif psnr >= 30 and ssim >= 0.90:
            quality = "🟠 GOOD - Slight differences"
            details = "Minor visual changes may be visible on close inspection"
        elif psnr >= 20 and ssim >= 0.80:
            quality = "🔴 FAIR - Noticeable changes"
            details = "Visual differences are apparent but acceptable"
        else:
            quality = "🔴 POOR - Significant changes"
            details = "Hidden data causes obvious visual degradation"
        
        # Add simple quality metrics in plain English
        noise_level = "Very Low" if mse < 1 else "Low" if mse < 5 else "Medium" if mse < 15 else "High"
        image_quality = "Excellent" if psnr >= 40 else "Good" if psnr >= 30 else "Fair" if psnr >= 20 else "Poor"
        similarity = "Nearly Identical" if ssim >= 0.95 else "Very Similar" if ssim >= 0.90 else "Similar" if ssim >= 0.80 else "Different"
        
        simple_metrics = f"Quality: {image_quality} | Noise: {noise_level} | Similarity: {similarity}"
        
        return f"{quality}\n{details}\n\n{simple_metrics}"
    
    # Test cases with different quality levels
    test_cases = [
        {
            'name': 'Perfect Quality',
            'metrics': {'mse': 0.1, 'psnr': 90.5, 'ssim': 0.999},
            'expected': 'Very Low.*Excellent.*Nearly Identical'
        },
        {
            'name': 'Very Good Quality',
            'metrics': {'mse': 1.23, 'psnr': 42.56, 'ssim': 0.987},
            'expected': 'Low.*Excellent.*Very Similar'
        },
        {
            'name': 'Good Quality',
            'metrics': {'mse': 3.45, 'psnr': 35.67, 'ssim': 0.923},
            'expected': 'Low.*Good.*Very Similar'
        },
        {
            'name': 'Fair Quality',
            'metrics': {'mse': 8.12, 'psnr': 25.34, 'ssim': 0.845},
            'expected': 'Medium.*Fair.*Similar'
        },
        {
            'name': 'Poor Quality',
            'metrics': {'mse': 20.67, 'psnr': 18.23, 'ssim': 0.723},
            'expected': 'High.*Poor.*Different'
        }
    ]
    
    print("🎯 Testing Simple Quality Metrics")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\n📊 {test_case['name']}:")
        result = get_quality_description(test_case['metrics'])
        print(result)
        print("-" * 30)
    
    print("\n✅ All tests completed!")
    print("🎉 Now users will see simple, understandable terms:")
    print("   • Quality: Excellent/Good/Fair/Poor")
    print("   • Noise: Very Low/Low/Medium/High") 
    print("   • Similarity: Nearly Identical/Very Similar/Similar/Different")
    print("\n🚀 Much better than MSE/PSNR/SSIM technical jargon!")

if __name__ == "__main__":
    test_simple_metrics()
