document.getElementById("submitQuiz").addEventListener("click", function () {
  let correctAnswers = 0;
  const totalQuestions = document.querySelectorAll(".question").length;

  // Check all questions
  const questions = document.querySelectorAll(".question");
  questions.forEach((question, index) => {
    const selectedOption = question.querySelector('input[type="radio"]:checked');
    if (selectedOption && selectedOption.value === "correct") {
      correctAnswers++;
    }
  });

  // Display the result
  const resultContainer = document.getElementById("quizResult");
  if (correctAnswers === totalQuestions) {
    resultContainer.textContent = `Awesome! You got ${correctAnswers}/${totalQuestions} correct!`;
    resultContainer.style.color = "green";
  } else {
    resultContainer.textContent = `You got ${correctAnswers}/${totalQuestions} correct. Better luck next time!`;
    resultContainer.style.color = "red";
  }
});
